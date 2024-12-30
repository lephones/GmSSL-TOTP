# GMSSL-TOTP
基于[https://github.com/guanzhi/GmSSL](https://github.com/guanzhi/GmSSL)

原项目新建了totp目录，所有totp相关代码均在totp目录中

代码来源于《信息安全技术 动态口令密码应用技术规范》，目前国内像某H家的totp软件，就使用此sm3算法

请先build对应平台的.a文件，再将对静态库复制到lib目录，参考CMakeLists.txt

例：Android 
注意，Android工程中的，CMakeLists文件结合totp目录修改
```
makedir build 
cd build
cmake .. -DCMAKE_TOOLCHAIN_FILE=$ANDROID_NDK_HOME/build/cmake/android.toolchain.cmake -DANDROID_ABI=arm64-v8a -DANDROID_PLATFORM=21 -DCMAKE_BUILD_TYPE=Release -DBUILD_SHARED_LIBS=OFF
```
