::Metasploit Modules

1. mof_persist.rb

   A simple persistence script to mimic the functionality of the default persistence meterpreter module, but by accomplishing such via Managed Object Files and powershell.  May require admiistrative privileges to execute.  To use, just simply copy this module to $msf_path/modules/post/windows/.

2. ms16_032_secondary_logon_handle_privesc.rb

   A port of b33f's (@FuzzySec) powershell version of ms16_032 into a metasploit module.  Currently, the payloads are piped into an uploaded text document containing a compressed powershell script of the chosen payload.  The Delete option and Timeout options are currently broken.  To use, just simply copy this module to #msf_path/modules/exploit/windows/local/ (and issue a reload_all if msf is currently running).
