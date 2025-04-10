#include <fstream>
#include <iostream>
#include <filesystem>
#include <system_error>

#include "oatpp/web/server/HttpConnectionHandler.hpp"
#include "oatpp/network/Server.hpp"
#include "oatpp/network/tcp/server/ConnectionProvider.hpp"
#include "oatpp/Environment.hpp"
#include "oatpp/macro/codegen.hpp"
#include "oatpp/json/ObjectMapper.hpp"
#include "oatpp/data/resource/File.hpp"

#include "oatpp/web/mime/multipart/TemporaryFileProvider.hpp"
#include "oatpp/web/mime/multipart/Reader.hpp"
#include "oatpp/web/mime/multipart/PartList.hpp"

#include "oatpp/encoding/Base64.hpp"

namespace multipart = oatpp::web::mime::multipart;
namespace fs = std::filesystem;

void traverse_directory(const fs::path& dir_path, std::vector<fs::path>& results) {
    // 检查路径是否存在且是一个目录
    if (fs::exists(dir_path) && fs::is_directory(dir_path)) {
        // 遍历目录中的所有条目（文件和子目录）
        for (const auto& entry : fs::directory_iterator(dir_path)) {
            // 打印当前条目的路径
            auto path = entry.path();
            if (path.has_extension() && path.extension() == ".sym") {
                results.push_back(path);
            }
            // 如果是目录，则递归遍历
            if (fs::is_directory(entry.status())) {
                traverse_directory(path, results);
            }
        }
    }
    else {
        std::cerr << dir_path << " is not a directory or does not exist." << std::endl;
    }
}

bool readBinaryFileToString(const std::string& filePath, std::string& output) {
    // 以二进制模式打开文件
    std::ifstream inputFile(filePath, std::ios::binary);

    // 检查文件是否成功打开
    if (!inputFile) {
        std::cerr << "Failed to open file: " << filePath << std::endl;
        return false;
    }

    // 获取文件大小
    inputFile.seekg(0, std::ios::end);
    std::streamsize size = inputFile.tellg();
    inputFile.seekg(0, std::ios::beg);

    if (size == -1) {
        std::cerr << "Failed to determine the file size." << std::endl;
        return false;
    }

    // 预分配字符串的大小
    output.clear();
    output.resize(static_cast<size_t>(size));

    // 读取文件内容到字符串中
    if (!inputFile.read(&output[0], size)) {
        std::cerr << "Error occurred while reading the file." << std::endl;
        return false;
    }

    // 关闭文件
    inputFile.close();

    return true;
}

#ifdef _WIN32

#include <Windows.h>

bool exec_base(const char* cmd, const char* curent_dir, std::string* output, int* exit_code) {

    OATPP_LOGi("MyApp", "exec_base curent_dir:{} cmd:{}", curent_dir, cmd);

    const bool include_stderr = false;

    HANDLE out_read = nullptr;
    HANDLE out_write = nullptr;

    SECURITY_ATTRIBUTES sa_attr;
    // Set the bInheritHandle flag so pipe handles are inherited.
    sa_attr.nLength = sizeof(SECURITY_ATTRIBUTES);
    sa_attr.bInheritHandle = TRUE;
    sa_attr.lpSecurityDescriptor = nullptr;

    // Create the pipe for the child process's STDOUT.
    if (!CreatePipe(&out_read, &out_write, &sa_attr, 0)) {
        OATPP_LOGi("MyApp", "Failed to create pipe");
        return false;
    }

    // Ensure the read handles to the pipes are not inherited.
    if (!SetHandleInformation(out_read, HANDLE_FLAG_INHERIT, 0)) {
        OATPP_LOGi("MyApp", "Failed to disabled pipe inheritance");
        return false;
    }

    STARTUPINFO start_info = {};

    start_info.cb = sizeof(STARTUPINFO);
    start_info.hStdOutput = out_write;
    // Keep the normal stdin.
    start_info.hStdInput = GetStdHandle(STD_INPUT_HANDLE);
    if (include_stderr) {
        start_info.hStdError = out_write;
    }
    else {
        start_info.hStdError = GetStdHandle(STD_ERROR_HANDLE);
    }
    start_info.dwFlags |= STARTF_USESTDHANDLES;

    // Create the child process.
    PROCESS_INFORMATION process_info = {};
    bool bCreated = CreateProcessA(nullptr, (char*)cmd, nullptr,
        nullptr,
        TRUE,  // Handles are inherited.
        0,
        NULL,
        curent_dir, &start_info, &process_info);

    if (!bCreated) {
        DWORD dwErrcode = GetLastError();
        OATPP_LOGi("MyApp", "Failed to create process, error:{}", dwErrcode);
        return false;
    }

    // Close our writing end of pipe now. Otherwise later read would not be able
    // to detect end of child's output.
    CloseHandle(out_write);

    // Read output from the child process's pipe for STDOUT
    const int kBufferSize = 1024;
    char buffer[kBufferSize];

    for (;;) {
        DWORD bytes_read = 0;
        BOOL success =
            ::ReadFile(out_read, buffer, kBufferSize, &bytes_read, nullptr);
        if (!success || bytes_read == 0)
            break;
        output->append(buffer, bytes_read);
    }

    // Let's wait for the process to finish.
    WaitForSingleObject(process_info.hProcess, INFINITE);

    DWORD process_exit_code = 0;
    if (exit_code && GetExitCodeProcess(process_info.hProcess, &process_exit_code)) {
        *exit_code = static_cast<int>(process_exit_code);
    }

    return process_exit_code == 0;
}

std::string exec(const char* cmd, const char* curent_dir = nullptr) {
    std::string result;
    int exit_code = 0;
    exec_base(cmd, curent_dir, &result, &exit_code);
    return result;
}

std::string get_current_dir() {
    std::string result;
    char buffer[1024];
    DWORD dwRet = GetCurrentDirectoryA(sizeof(buffer), buffer);
    if (dwRet != 0) {
        result = buffer;
    }
    return result;
}

std::string normalize_path_sep(const std::string& path) {
    std::string new_path = path;
    for (size_t i = 0; i < new_path.length(); i++) {
        if (new_path[i] == '/') {
            new_path[i] = '\\';
        }
    }
    return new_path;
}

std::string path_append(const std::string& path, const std::string& name) {
    std::string result;
    if (path[path.size() - 1] == '\\') {
        if (name[name.size() - 1] == '\\') {
            result = path + name.substr(1);
        }
        else {
            result = path + name;
        }
    }
    else {
        if (name[name.size() - 1] == '\\') {
            result = path + name;
        }
        else {
            result = path + '\\' + name;
        }
    }
    return normalize_path_sep(result);
}


#define sign_tool "sign_tool.bat"

#else

#include <unistd.h>

std::string exec(const char* cmd) {
    char buffer[128];
    std::string result;
    std::unique_ptr<FILE, decltype(&pclose)> pipe(popen(cmd, "r"), pclose);
    if (!pipe) {
        return result;
    }
    while (fgets(buffer, sizeof(buffer), pipe.get()) != nullptr) {
        result += buffer;
    }
    return result;
}

std::string get_current_dir() {
    std::string result;
    char buffer[1024];
    if (getcwd(buffer, sizeof(buffer)) != nullptr) {
        result = buffer;
    }
    return result;
}

std::string normalize_path_sep(const std::string& path) {
    std::string new_path = path;
    for (size_t i = 0; i < new_path.length(); i++) {
        if (new_path[i] == '\\') {
            new_path[i] = '/';
        }
    }
    return new_path;
}

std::string path_append(const std::string& path, const std::string& name) {
    std::string result;
    if (path[path.size() - 1] == '/') {
        if (name[name.size() - 1] == '/') {
            result = path + name.substr(1);
        }
        else {
            result = path + name;
        }
    }
    else {
        if (name[name.size() - 1] == '/') {
            result = path + name;
        }
        else {
            result = path + '/' + name;
        }
    }
    return normalize_path_sep(result);
}

#define sign_tool  "sign_tool.bat"

#endif

std::string trim(const std::string& str) {
    size_t first = str.find_first_not_of(" \t\n");
    if (std::string::npos == first) {
        return str;
    }
    size_t last = str.find_last_not_of(" \t\n");
    return str.substr(first, (last - first + 1));
}

std::vector<std::string> split(const std::string& s, char delimiter) {
    std::vector<std::string> tokens;
    std::istringstream tokenStream(s);
    std::string token;
    while (std::getline(tokenStream, token, delimiter)) {
        tokens.push_back(token);
    }
    return tokens;
}

std::vector<std::string> split_and_trim(const std::string& s, char delimiter) {
    std::vector<std::string> tokens;
    std::istringstream tokenStream(s);
    std::string token;
    while (std::getline(tokenStream, token, delimiter)) {
        tokens.push_back(trim(token));
    }
    return tokens;
}

std::vector<std::string> split(const std::string& s, const std::string& delimiter) {
    std::vector<std::string> tokens;
    size_t start = 0, end;
    while ((end = s.find(delimiter, start)) != std::string::npos) {
        tokens.push_back(s.substr(start, end - start));
        start = end + delimiter.length();
    }
    tokens.push_back(s.substr(start));
    return tokens;
}

std::vector<std::string> split_and_trim(const std::string& s, const std::string& delimiter) {
    std::vector<std::string> tokens;
    size_t start = 0, end;
    while ((end = s.find(delimiter, start)) != std::string::npos) {
        tokens.push_back(trim(s.substr(start, end - start)));
        start = end + delimiter.length();
    }
    tokens.push_back(trim(s.substr(start)));
    return tokens;
}

std::string read_string(const std::string& file_path) {
    std::string content;
    std::ifstream file(file_path.c_str());
    if (file.is_open()) {
        std::string line;
        while (std::getline(file, line)) {
            content += line;
            content += "\n";
        }
        file.close();
    }
    if (!content.empty()) {
        content = content.substr(0, content.size() - 1);
    }
    return content;
}

bool write_string(const std::string& file_path, const std::string &str) {
    std::ofstream file(file_path.c_str());
    if (file.is_open()) {
        file << str;
        file.close();
        return true;
    }
    return false;
}

/* Begin DTO code-generation */
#include OATPP_CODEGEN_BEGIN(DTO)

/**
 * Message Data-Transfer-Object
 */
class MessageDto : public oatpp::DTO {

    DTO_INIT(MessageDto, DTO /* Extends */)

    DTO_FIELD(Int32, statusCode);   // Status code field
    DTO_FIELD(String, message);     // Message field
    DTO_FIELD(String, content);     // Content field
    DTO_FIELD(String, filename);     // FileName field
};

/* End DTO code-generation */
#include OATPP_CODEGEN_END(DTO)


/**
 * Custom Request Handler
 */
class HelloHandler : public oatpp::web::server::HttpRequestHandler {
private:
    std::shared_ptr<oatpp::data::mapping::ObjectMapper> m_objectMapper;
    std::string m_root_path;
    std::string m_static_path;
public:

    /**
     * Constructor with object mapper.
     * @param objectMapper - object mapper used to serialize objects.
     */
    explicit HelloHandler(const std::shared_ptr<oatpp::data::mapping::ObjectMapper>& objectMapper)
            : m_objectMapper(objectMapper), m_root_path(get_current_dir())
    {
        m_static_path = path_append(m_root_path, "static");
    }

    /**
     * Handle incoming request and return outgoing response.
     */
    std::shared_ptr<OutgoingResponse> handle(const std::shared_ptr<IncomingRequest>& request) override {

        std::string content;
        std::string path;
        std::string path_tail = request->getPathTail();
        if (path_tail.empty()){
            path = path_append(m_static_path, "/");
            path = path_append(path, "index.html");
        }else if (path_tail[path_tail.size()-1] == '/') {
            path = path_append(m_static_path, path_tail);
            path = path_append(path, "index.html");
        }else{
            path = path_append(m_static_path, request->getPathTail());
        }


        if (readBinaryFileToString(path, content)) {

            OATPP_LOGd("file", "open {} success.", path);

            if (path_tail.find("download/") != -1) {
                std::remove(path.c_str());
            }

            return ResponseFactory::createResponse(Status::CODE_200, content);
        }else{
            OATPP_LOGd("file", "open {} failed.", path)
            return ResponseFactory::createResponse(Status::CODE_404);
        }
    }

};

/**
 * Custom Request Handler
 */
class  SignFileHandler : public oatpp::web::server::HttpRequestHandler {
private:
    std::shared_ptr<oatpp::data::mapping::ObjectMapper> m_objectMapper;
    std::string m_root_path;
public:

    /**
     * Constructor with object mapper.
     * @param objectMapper - object mapper used to serialize objects.
     */
    explicit SignFileHandler(const std::shared_ptr<oatpp::data::mapping::ObjectMapper>& objectMapper)
            : m_objectMapper(objectMapper), m_root_path(get_current_dir())
    {
    }

    /**
     * Handle incoming request and return outgoing response.
     */
    std::shared_ptr<OutgoingResponse> handle(const std::shared_ptr<IncomingRequest>& request) override {

        /* create multipart object */
        multipart::PartList multipart(request->getHeaders());

        /* create multipart reader */
        multipart::Reader multipartReader(&multipart);

        /* setup reader to stream parts to a temporary files by default */
        multipartReader.setDefaultPartReader(multipart::createTemporaryFilePartReader(path_append(m_root_path, "sign_files") /* /tmp directory */));

        /* upload multipart data */
        request->transferBody(&multipartReader);

        std::string sign_file;
        std::string sign_file_name;
        std::string response_type = "file";
        /* list all parts and locations to corresponding temporary files */
        auto parts = multipart.getAllParts();
        for(auto& p : parts) {
            if (p->getName()=="file"){
                sign_file = p->getPayload()->getLocation();
            }
            if (p->getName() == "file_name") {
                sign_file_name = read_string(p->getPayload()->getLocation());
            }
            if (p->getName() == "response_type") {
                response_type = read_string(p->getPayload()->getLocation());
            }
            OATPP_LOGd("MyApp", "upload: field_name={}, file_name={}, response_type={}", p->getName(), sign_file_name, response_type)
        }

        std::string bin_path = path_append(m_root_path, "bin");
        std::string sign_tool_path = bin_path + "\\" + sign_tool;

        sign_file = normalize_path_sep(sign_file);

        std::string log, cmd, os, cpu;
        cmd = "\"";
        cmd += sign_tool_path;
        cmd += "\" \"";
        cmd += sign_file;
        cmd += "\"";
        log = exec(cmd.c_str(), bin_path.c_str());

        OATPP_LOGi("MyApp", "Console:{}", log);

        std::error_code e;
        auto message = MessageDto::createShared();
        message->statusCode = 0;
        message->message = log;

        bool sign_success = log.find("Number of files successfully Signed: 1") != -1;

        if (sign_success) {
            if (response_type == "json_content" || response_type == "file") {

                std::string file_content;
                if (readBinaryFileToString(sign_file, file_content)) {
                    message->statusCode = 1;

                    if (response_type == "file") {
                        // 设置响应头
                        auto response = ResponseFactory::createResponse(Status::CODE_200, file_content);
                        response->putHeader(Header::CONTENT_TYPE, "application/octet-stream"); // 设置正确的 MIME 类型
                        if (!sign_file_name.empty())
                            response->putHeader("Content-Disposition", "attachment; filename=\"" + sign_file_name + "\""); // 设置 Content-Disposition 以触发下载
                        response->putHeader(Header::CONTENT_LENGTH, std::to_string(file_content.size())); // 设置内容长度

                        return response;
                    }

                    if (response_type == "json_content") {
                        message->content = oatpp::encoding::Base64::encode(file_content);
                    }
                }
            }
            else {

                std::string url_path;
                auto pos = sign_file.find("sign_files");
                if (pos != -1) {
                    url_path = sign_file.substr(pos + 11);
                }

                std::string new_path = path_append(m_root_path, "static/download/" + url_path);
                if (std::rename(sign_file.c_str(), new_path.c_str()) == 0) {
                    message->statusCode = 1;
                    message->filename = "download/" + url_path;
                }
            }
        }
        else {
            if (response_type == "file") {
                // 设置响应头

                auto response = ResponseFactory::createResponse(Status::CODE_200, log);
                response->putHeader(Header::CONTENT_TYPE, "application/octet-stream"); // 设置正确的 MIME 类型
                if (!sign_file_name.empty())
                    response->putHeader("Content-Disposition", "attachment; filename=\"" + sign_file_name + "\""); // 设置 Content-Disposition 以触发下载
                response->putHeader(Header::CONTENT_LENGTH, std::to_string(log.size())); // 设置内容长度

                return response;
            }
        }

        return ResponseFactory::createResponse(Status::CODE_200, message, m_objectMapper);
    }

};

void run() {

    std::string current_dir = get_current_dir();

    OATPP_LOGi("MyApp", "current_dir is {}", current_dir)


    auto objectMapper = std::make_shared<oatpp::json::ObjectMapper>();

    /* Create Router for HTTP requests routing */
    auto router = oatpp::web::server::HttpRouter::createShared();

    /* Route GET - "/hello" requests to Handler */
    router->route("GET", "/*", std::make_shared<HelloHandler>(objectMapper));

    /* Route GET - "/hello" requests to Handler */
    router->route("POST", "/sign_file", std::make_shared<SignFileHandler>(objectMapper));

    /* Create HTTP connection handler with router */
    auto connectionHandler = oatpp::web::server::HttpConnectionHandler::createShared(router);

    /* Create TCP connection provider */
    auto connectionProvider = oatpp::network::tcp::server::ConnectionProvider::createShared({"0.0.0.0", 8080, oatpp::network::Address::IP_4});

    /* Create server which takes provided TCP connections and passes them to HTTP connection handler */
    oatpp::network::Server server(connectionProvider, connectionHandler);

    /* Print info about server port */
    OATPP_LOGi("MyApp", "Server running on port {}", connectionProvider->getProperty("port").std_str())

    /* Run server */
    server.run();
}

int main() {

    /* Init oatpp Environment */
    oatpp::Environment::init();

    /* Run App */
    run();

    /* Destroy oatpp Environment */
    oatpp::Environment::destroy();

    return 0;

}
