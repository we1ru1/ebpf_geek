# 单行注释

#[[这是多行注释
    多行注释  ]]

# SET(VAR "VALUE")  # 定义变量
set(SRC_LIST add.c;div.c;main.c;multi.c;sub.c)  # 定义变量
cmake_minimum_required(VERSION 3.0)     # cmake最低版本要求
project(CALC)         # 项目名称
add_executable(app ${SRC_LIST})   # 生成可执行文件，exe文件吗和project名没有任何关系