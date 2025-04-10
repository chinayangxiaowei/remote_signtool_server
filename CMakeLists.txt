cmake_minimum_required(VERSION 3.1)

set(project_name remote_signtool_server) ## rename your project here

project(${project_name})

set(CMAKE_CXX_STANDARD 20)

## link libs

find_package(oatpp 1.4.0 REQUIRED)

## add executables

add_executable(${project_name}
        src/App.cpp
)

target_link_libraries(${project_name} PRIVATE oatpp::oatpp)

set_target_properties(${project_name} PROPERTIES
        CXX_STANDARD 20
        CXX_EXTENSIONS OFF
        CXX_STANDARD_REQUIRED ON
)

