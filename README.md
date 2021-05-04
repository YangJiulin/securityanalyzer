# securityanalyzer
Android APP漏洞分析平台
### 查看avd列表
    emulator -list-avds
### avd系统目录
>系统目录包含模拟器用于模拟操作系统的 Android 系统映像。它具有由所
>有相同类型的 AVD 共享的特定于平台的只读文件，包括 API 级别、CPU 
>架构和 Android 变体。默认位置如下：
   - Mac OS X 和 Linux 
     - ~/Library/Android/sdk/system-images/android-apiLevel/variant/arch/
   - Microsoft Windows XP
     - C:\Documents and Settings\user\Library\Android\sdk\system-images\android-apiLevel\variant\arch\
   - Windows Vista
    C:\Users\user\Library\Android\sdk\system-images\android-apiLevel\variant\arch\
### 启动avd命令选项
    -writable-system
    emulator -avd <non_production_avd_name> -writable-system -no-snapshot
> 使用此选项在模拟会话期间创建可写系统映像。为此，请执行以下操作：
    使用 -writable-system 选项启动虚拟设备。
    从命令终端输入 adb remount 命令，让模拟器以读/写方式重新装载 system/（默认情况下，它以只读方式装载）。
    
**请注意，使用此标记将创建系统映像的临时副本，该副本可能非常大（数百 MB），但在模拟器退出时将被销毁。***