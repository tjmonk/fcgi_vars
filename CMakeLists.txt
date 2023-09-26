cmake_minimum_required(VERSION 3.10)

include(GNUInstallDirs)

project(fcgi_vars
	VERSION 0.1
    DESCRIPTION "Fast CGI Variable Server query module"
)

find_library( LIB_FCGI fcgi REQUIRED )

add_executable( ${PROJECT_NAME}
	src/fcgi_vars.c
)

target_include_directories( ${PROJECT_NAME}
	PRIVATE inc
)

target_compile_options( ${PROJECT_NAME}
	PUBLIC
	-Wall
	-Wextra
	-Wpedantic
	-Werror
)

target_link_libraries( ${PROJECT_NAME}
	varserver
    ${LIB_FCGI}
)

install(TARGETS ${PROJECT_NAME}
	RUNTIME DESTINATION ${CMAKE_INSTALL_BINDIR}
    PERMISSIONS OWNER_READ OWNER_WRITE OWNER_EXECUTE GROUP_READ GROUP_EXECUTE WORLD_READ WORLD_EXECUTE SETUID

)