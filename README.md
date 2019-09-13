# dd_dlopen

绕过android 7.0 dlopen对系统库无效的限制

注意：这里没有递归解析DT_NEEDED，所以，解析符号的时候，应该要清楚当前的符号在哪个so内，将其路径传进来。

很多开源库是解析Section Header，这个是不准的，因为Section Header是可以做手脚的
另外这里，解析符号，利用了gnu_hash, 或者dt_hash快速查找相应的符号。

不过，目前对于bloom filter还有点小问题，但是不妨碍该库正确工作.
