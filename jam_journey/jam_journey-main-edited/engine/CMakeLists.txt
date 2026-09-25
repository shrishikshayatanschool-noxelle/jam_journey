cmake_minimum_required(VERSION 3.16)
project(bodyguard_policy LANGUAGES CXX)

add_library(bodyguard_policy src/policy.cpp)
target_include_directories(bodyguard_policy PUBLIC include)
target_compile_features(bodyguard_policy PUBLIC cxx_std_17)

add_executable(bodyguard-policy src/main.cpp)
target_link_libraries(bodyguard-policy PRIVATE bodyguard_policy)

