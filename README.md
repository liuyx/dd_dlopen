# dd_dlopen

绕过android 7.0 dlopen对系统库无效的限制

注意：这里没有递归解析DT_NEEDED，所以，解析符号的时候，应该要清楚当前的符号在哪个so内，将其路径传进来。
