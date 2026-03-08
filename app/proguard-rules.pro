# Keep Tor native library loading
-keep class info.guardianproject.** { *; }
-dontwarn net.freehaven.tor.control.RawEventListener
-dontwarn net.freehaven.tor.control.TorControlConnection

# Keep our service classes (referenced by manifest)
-keep class com.torproxy.TorVpnService { *; }
-keep class com.torproxy.ApiService { *; }
-keep class com.torproxy.BootReceiver { *; }
-keep class com.torproxy.TorManager { *; }
