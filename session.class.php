<?php
///######## IF FILE IS NOT APPROACHED DIRECTLY
defined('FWK') or exit('<strong>error</strong>, access denied!');



///########-------------------------------------------------------------
///########-------------------------------------------------------------
///######## CLASS TO HANDLE SESSIONS
///########-------------------------------------------------------------
///########-------------------------------------------------------------
class SESSION {
	/// **** BASIC CLASS VARIABLES
    const			SESSION_STARTED				= true;
    const			SESSION_NOT_STARTED			= false;



    /// **** SESSION CLASS CONFIGURATION
    public static	$sessiondir					= NULL;
    public static	$root						= NULL;



    /// **** THE STATE OF THE SESSION
    private	static	$sessionState				= self::SESSION_NOT_STARTED;
    private static	$CurrentSession				= NULL;



    /// **** THE ONLY INSTANCE OF THE CLASS
    private static	$instance;



    /// **** SESSION CONFIGURATION
    public static	$limit						= 432000;
    public static	$secure						= false;
	public static	$domain						= NULL;
	public static	$httponly					= true;
	public static	$SessionName				= NULL;
    public static   $path                       = NULL;
	public static	$setsessioncookie			= true;



	/// **** CUSTOM CALLER FUNCTIONS
	private static	$CallerFunctions			= array();



	/// **** CURRENT USER VARS
	public static	$CurrentIP					= NULL;
	public static	$CurrentBrowser				= NULL;
	public static	$CurrentProtocol			= NULL;






	///########-------------------------------------------------------------
	///########-------------------------------------------------------------
	///######## AUTOLOADING FUNCTION TO INITIATE THE ENTIRE CLASS
	///########-------------------------------------------------------------
	///########-------------------------------------------------------------
    public static function INIT(){
		///########==================================================
    	///######## IF THE ROOT DIRECTORY HAS BEEN DEFINED
		///########==================================================
    	if(defined('ROOT') === true){
    		self::$root = ROOT;
    	}
		///########==================================================



		///########==================================================
		///####### SET A SESSION NAME
		///########==================================================
		self::$SessionName	= md5(self::$domain);
		///########==================================================
    }



	///########-------------------------------------------------------------
	///########-------------------------------------------------------------
	///######## FUNCTION TO PREVENT SESSION HIJACKING
	///########-------------------------------------------------------------
	///########-------------------------------------------------------------
	protected static function preventHijacking(){
		///######## IF THE BASIC DATA IS MISSING
		if(
			/// **** SESSION IP ADDRESS
				(
					/// **** IF THE IP ADDRESS HAS BEEN SET
						(isset($_SESSION['SessionIPaddress'])	=== true)
					&&
					/// **** IF THE IP ADDRESS IS MISMATHCHING
						($_SESSION['SessionIPaddress']			== self::$CurrentIP)
				)
			&&
			/// **** SESSION USER AGENT
				(
					/// **** IF THE USER AGENT HAS NOT BEEN SET
						(isset($_SESSION['SessionuserAgent'])	=== true)
					&&
					/// **** IF THE BROWSER IS MATCHING
						($_SESSION['SessionuserAgent']			== self::$CurrentBrowser)
				)
			&&
			/// **** IF THE SESSION FILE HAS CORRECT DATA
				(self::CheckSessionFile()						=== true)
			&&
			/// **** IF THE CUSTOM CALLER HAS ALLOWS EXECUTION
				(self::CustomCallerOnLoad()					    === true)
		){
			///########==================================================
			///######## RETURN TRUE
			///########==================================================
			return(true);
			///########==================================================
		}
		///######## IF NOT MATCH
		else{
			///########==================================================
			///######## RETURN FALSE
			///########==================================================
			return(false);
			///########==================================================
		}
	}



	///########-------------------------------------------------------------
	///########-------------------------------------------------------------
	///######## FUNCTION TO CONFIGURE THE SYSTEM
	///########-------------------------------------------------------------
	///########-------------------------------------------------------------
	public static function configure($setting, $value){
		///######## SET THE ALLOWED CONFIGURATION OPTIONS
		$Allowed = array(
							'limit'					=>			true,
							'secure'				=>			true, 
							'domain'				=>			true,
							'httponly'				=>			true,
							'sessiondir'			=>			true,
							'setsessioncookie'		=>			true
						);

		///########==================================================
		///######## IF THE CONFIGURATION IS VALID
		///########==================================================
	    if(isset($Allowed[$setting]) === true){
	    	///######## INITIATE NEW INSTANCE
	        self::${$setting} = $value;
	    }
	    ///######## IF THE CONFIGURATION IS INVALID
	    else{
	    	///######## GIVE AN ERROR MESSAGE
	    	echo '<strong>error</strong>, invalid session configuration value';
	    }
	    ///########==================================================
	}



	///########-------------------------------------------------------------
	///########-------------------------------------------------------------
	///######## FUNCTION TO CONFIGURE THE SYSTEM WITH CUSTOM CALLERS
	///########-------------------------------------------------------------
	///########-------------------------------------------------------------
	public static function customcaller($callers){
    	///######## SETTING THE CUSTOM CALLER FUNCTIONS
        self::$CallerFunctions = $callers;
	}



	///########-------------------------------------------------------------
	///########-------------------------------------------------------------
	///######## FUNCTION TO RETURN THE INSTANCE OF THE SESSION
	///########-------------------------------------------------------------
	///########-------------------------------------------------------------
    public static function getInstance($SessionName = NULL){
    	///######## IF THE SESSION HAS NOT BEEN STARTED YET
        if(isset(self::$instance) === false){
        	///######## INITIATE NEW INSTANCE
            self::$instance = new self;
        }
		///######## START A NEW SESSION
		self::$instance->startSession($SessionName);

		///########==================================================
		///######## RETURN THE SESSION INSTANCE
		///########==================================================
		return(self::$instance);
		///########==================================================
    }



	///########-------------------------------------------------------------
	///########-------------------------------------------------------------
	///######## FUNCTION TO SAVE A SESSION
	///########-------------------------------------------------------------
	///########-------------------------------------------------------------
    private static function SaveSession(){
		///######## IF A SESSION COOKIE SHOULD BE SET
		if(self::$setsessioncookie === true){
			///######## STORING SESSION ID IN A COOKIE
			self::SetSessionCookie();
		}



		///########==================================================
		///######## WRITE THE SESSION
		///########==================================================
		///######## IF A SESSION DIRECTORY HAS BEEN SET
		if(self::$sessiondir !== NULL){
			///######## CALL THE WRITE SESSION FUNCTION
			self::WriteSession();
		}
		///########==================================================
    }



	///########-------------------------------------------------------------
	///########-------------------------------------------------------------
	///######## FUNCTION TO SET A SESSION COOKI
	///########-------------------------------------------------------------
	///########-------------------------------------------------------------
    public static function SetSessionCookie(){
		///########==================================================
		///######## STORING THE SESSION ID IN A COOKIE
		///########==================================================
		setcookie(
					self::$SessionName,				/// **** SET THE COOKIE NAME
					session_id(),					/// **** SET THE COOKIE CONTENTS
					(time() + self::$limit)			/// **** MAX DURATION OF THE COOKIE LIFETIME
				);
		///########==================================================
    }



	///########-------------------------------------------------------------
	///########-------------------------------------------------------------
	///######## FUNCTION TO RESTORE A SESSION
	///########-------------------------------------------------------------
	///########-------------------------------------------------------------
    private static function RestoreSession(){
		///######## IF A COOKIE HAS BEEN SET
		if(
			/// **** IF A COOKIE HAS BEEN SET
				(isset($_COOKIE[self::$SessionName]) === true)
			&&
			/// **** IF THE COOKIE HAS ANY CONTENTS
				(empty($_COOKIE[self::$SessionName]) === false)
			){
			///######## GET THE COOKIE VARIABLES
			$LoadSessionId	= $_COOKIE[self::$SessionName];
			///######## SET THE SESSION ID
			session_id($LoadSessionId);
			///######## SAVING THE SESSION ID
			self::$CurrentSession = $LoadSessionId;
		}
		///######## IF THE COOKIE IS INVALID
		else{
			///######## UNSET THE SESSION COOKIE
			unset($_COOKIE[self::$domain]);
		}
	}



	///########-------------------------------------------------------------
	///########-------------------------------------------------------------
	///######## FUNCTION TO START THE SESSION
	///########-------------------------------------------------------------
	///########-------------------------------------------------------------
    public static function STARTSESSION($SetSessionName = NULL){
    	///######## IF THE SESSION STATE IS INACTIVE
		if(self::$sessionState == self::SESSION_NOT_STARTED){
			///######## IF A SESSION COOKIE SHOULD BE SET
			if(self::$setsessioncookie === true){
                ///######## SETTINGS ARRAY
                $SessionSettings = array(
											'session.cookie_lifetime'       =>          self::$limit,			/// **** LIFETIME OF THE SESSION COOKIE (in seconds)
											///'session.cookie_path'           =>          self::$path,			/// **** THE DOMAIN FOR WHERE THE COOKIE WILL WORK. (single /  for all paths on the domain.)
											'session.cookie_domain'         =>          self::$domain,			/// **** DEFINE THE DOMAIN NAME
											'session.cookie_secure'         =>          self::$secure,			/// **** ONLY BY SECURE CONNECTIONS
											'session.cookie_httponly'       =>          self::$httponly			/// **** INDICATE THAT THE SESSION COOKIE IS AVAILABLE THROUGH HTTP PROTOCOLS ONLY (not by Javascript)
                                        );

                ///########==================================================
				///######## SET THE SESSION COOKIE PARAMETERS
				///########==================================================
                ///######## RUN THROUGH ALL SETTINGS
                foreach($SessionSettings as $Option => $Setting){
                    ///######## IF THE OPTION IS NOT EMPTY
                    if($Setting !== NULL){
                        ///######## SET THE SETTING
                        ini_set($Option, $Setting);
                    }
                }
				///########==================================================
			}



			///########==================================================
			///######## SET THE SESSION NAME
			///########==================================================
			///######## IF A SESSION NAME HAS BEEN SET
			if($SetSessionName !== NULL){
				///######## SET A SESSION NAME TO THE CLASS
				self::$SessionName = $SetSessionName;
				///######## SET THE SESSION NAME
				session_name($SetSessionName);
			}
			///######## IF NO SESSION NAME HAS BEEN SET
			else{
				///######## SET A DEFAULT SESSION NAME
				session_name(self::$SessionName);
			}
			///########==================================================



			///########==================================================
			///######## SET THE SESSION RUNTIME
			///########==================================================
			ini_set('session.gc_probability', 0);
			///######## START THE SESSION
			self::$sessionState = @session_start();
			///######## OPTIONALLY RESTART AN EXISTING SESSION
			self::RestoreSession();
			///########==================================================



			///######## PROTECT THE SESSION AGAINST HIJACKING
			if(self::preventHijacking() === false){
				///######## RESET THE SESSION
				$_SESSION						= array();
				$_SESSION['SessionIPaddress']	= self::$CurrentIP;
				$_SESSION['SessionuserAgent']	= self::$CurrentBrowser;

				///####### SET THE SESSION COOKIE
				self::SaveSession();
			}
			///####### IF THE SESSION IS CORRECT
			else{
				///######## LOAD THE SESSION ID
				self::$CurrentSession = session_id();
			}
		}
        ///######## IF THE SESSION ID HAS NOT YET BEEN DEFINED
        if(defined('SESSION_ID') === false){
            ///######## DEFINE THE SESSION ID
            define('SESSION_ID', self::$CurrentSession);
        }
		///########==================================================
		///######## GET THE SESSION STATE		
		///########==================================================
		return(self::$sessionState);
		///########==================================================
    }
   
   

	///########-------------------------------------------------------------
	///########-------------------------------------------------------------
	///######## FUNCTION TO SET SESSION DATA
    ///########
    ///########    Stores datas in the session.
    ///########    Example: $instance->foo = 'bar';
    ///########   
    ///########    @param    name    Name of the datas.
    ///########    @param    value    Your datas.
    ///########    @return    void
    ///########
	///########-------------------------------------------------------------
	///########-------------------------------------------------------------
    public function __set($name, $value){
    	///######## SET THE SESSION DATA
        $_SESSION[$name] = $value;
    }
   

   
	///########-------------------------------------------------------------
	///########-------------------------------------------------------------
	///######## FUNCTION TO GET SESSION DATA
    ///########
    ///########    Gets datas from the session.
    ///########    Example: echo $instance->foo;
    ///########   
    ///########    @param    name    Name of the datas to get.
    ///########    @return    mixed    Datas stored in session.
    ///########
	///########-------------------------------------------------------------
	///########-------------------------------------------------------------
    public function __get($name){
    	///######## IF THE SESSION KEY HAS BEEN SET
	    if(isset($_SESSION[$name]) === true){
		    ///########==================================================
		    ///######## SET THE SESSION NAME
		    ///########==================================================
            return($_SESSION[$name]);
            ///########==================================================
        }
    }



	///########-------------------------------------------------------------
	///########-------------------------------------------------------------
	///######## FUNCTION CHECK IF DATA HAS BEEN SET
	///########-------------------------------------------------------------
	///########-------------------------------------------------------------
    public function __isset($name){
		///########==================================================
	    ///######## RETURN BOOL IF SESSION DATA HAS BEEN SET
	    ///########==================================================
    	return(isset($_SESSION[$name]));
    	///########==================================================
    }



	///########-------------------------------------------------------------
	///########-------------------------------------------------------------
	///######## FUNCTION TO UNSET SESSION KEY DATA
	///########-------------------------------------------------------------
	///########-------------------------------------------------------------
    public function __unset($name){
    	///######## IF THE SESSION KEY HAS BEEN SET
    	if(isset($_SESSION[$name]) === true){
    		///######## UNSET THE SESSION KEY
	    	unset($_SESSION[$name]);
	    }
    }



	///########-------------------------------------------------------------
	///########-------------------------------------------------------------
	///######## FUNCTION GET A SESSION ID
	///########-------------------------------------------------------------
	///########-------------------------------------------------------------
    public function GetSession(){
	    ///########==================================================
		///######## RETURN THE SET SESSION ID
		///########==================================================
		return(self::$CurrentSession);
		///########==================================================
	}   

   

	///########-------------------------------------------------------------
	///########-------------------------------------------------------------
	///######## FUNCTION TO UNSET A SESSION
	///######## @return    bool    true is session has been deleted, else false.
	///########-------------------------------------------------------------
	///########-------------------------------------------------------------
    public static function DESTROY(){
    	///######## IF A SESSION HAS BEEN STARTED
    	if(self::$sessionState == self::SESSION_STARTED){
	        ///########==================================================
	        ///######## IF A CUSTOM CALLER FUNCTION HAS BEEN SET ON EXIT
	        ///########==================================================
			if(isset(self::$CallerFunctions['onexit']) === true){
				///######## SET THE FUNCTION TITLE
				$FunctionTitle = self::$CallerFunctions['onexit'];
				///######## EXECUTE THE CUSTOM CALLER FUNCTION
				$FunctionTitle(self::$CurrentSession);
			}
	        ///########==================================================



	    	///########==================================================
    		///######## IF THE SESSION HAS BEEN WRITTEN IN A  SESSION DIRECTORY
    		///########==================================================
    		///######## IF ANY SESSION DIR HAS BEEN GIVEN
    		if(self::$sessiondir !== NULL){
    			///######## DELETE THE SESSION FILE
    			self::DeleteSessionFile();
    		}
            ///########==================================================



			///########==================================================
    		///######## REGENERATE THE SESSION ID AND DELETE THE OLD ONE
    		///########==================================================
    		session_regenerate_id();
    		///########==================================================



			///########==================================================
    		///######## IF THE SESSION STATE IS NOT DESTROY
    		///########==================================================
            self::$sessionState = !session_destroy();
            ///########==================================================


            
            ///########==================================================
            ///####### RESET THE SESSION
            ///########==================================================
            $_SESSION = array();
			///########==================================================


            
            ///########==================================================
            ///####### UNSET THE SESSION
            ///########==================================================
            unset($_SESSION);
            session_unset();
            ///########==================================================



            ///########==================================================
			///######## SESSION COOKIE            
            ///########==================================================
            ///######## IF THE SESSION COOKIE EXISTS
            if(isset($_COOKIE[self::$SessionName]) === true){
            	///######## UNSET THE COOKIE SESSION
	            unset($_COOKIE[self::$SessionName]);
	        }
	        ///######## SET A COOKIE WITH NONSENSE DATA
			setcookie(self::$SessionName, NULL);
	    	///####### LOWER THE SESSION COOKIE
			setcookie(self::$SessionName, NULL, time()-42000, '/');
	        ///########==================================================



			///########==================================================
			///######## RETURN THE UNSET SESSION
			///########==================================================
			return(!self::$sessionState);
			///########==================================================
        }



		///########==================================================
		///######## DEFAULT RETURN FALSE
		///########==================================================
		return(false);
		///########==================================================
    }



	///########-------------------------------------------------------------
	///########-------------------------------------------------------------
	///######## FUNCTION TO WRITE THE SESSION TO A SET FOLDER
	///########-------------------------------------------------------------
	///########-------------------------------------------------------------
	private function WriteSession(){
		///######## CONTENTS
		$file_contents	= '{'.self::$CurrentIP.'},{'.self::$CurrentBrowser.'},{'.self::$CurrentProtocol.'}';
		///######## OPEN THE CACHE FILE
		$handle			= fopen(self::$root.self::$sessiondir.session_id().'.ses', 'a');
		///######## WRITE AWAY THE FILE CONTENTS
		fwrite($handle, $file_contents);
		///######## CLOSE THE FILE CONTENTS
		fclose($handle);
    }



	///########-------------------------------------------------------------
	///########-------------------------------------------------------------
	///######## FUNCTION TO CHECK IF A SESSION FILE EXISTS AND HAS THE CORRECT DATA
	///########-------------------------------------------------------------
	///########-------------------------------------------------------------
	private static function CheckSessionFile(){
		///######## IF A SESSION FILE HAS BEEN SET
		if(self::$sessiondir 			!== NULL){
			///######## COMPILE THE SESSION FILENAME
			$SessionFile = self::$root.self::$sessiondir.session_id().'.ses';
	
			///######## CHECK THE SESSION FILE
			if(
				/// **** IF THE SESSION FILE EXISTS
					(file_exists($SessionFile)			===	true)
				&&
				/// **** IF THE FILE CONTENTS ARE CORRECT
					(file_get_contents($SessionFile)	===	'{'.self::$CurrentIP.'},{'.self::$CurrentBrowser.'},{'.self::$CurrentProtocol.'}')
				){
				///######## SET THE FILE MODIFICATION DATE TO THE CURRENT MOMENT
				touch($SessionFile);

				///########==================================================
				///######## RETURN TRUE
				///########==================================================
				return(true);
				///########==================================================
			}
			///########==================================================
			///######## RETURN DEFAULT FALSE
			///########==================================================
			return(false);
			///########==================================================
		}
		///######## IF NO SESSION FILE SET
		else{
			///########==================================================
			///######## DEFAULT RETURN TRUE
			///########==================================================
			return(true);
			///########==================================================
		}
    }



	///########-------------------------------------------------------------
	///########-------------------------------------------------------------
	///######## FUNCTION TO DELETE A SESSION FILE
	///########-------------------------------------------------------------
	///########-------------------------------------------------------------
	private function DeleteSessionFile(){
		///######## COMPILE THE SESSION FILENAME
		$SessionFile = self::$root.self::$sessiondir.session_id().'.ses';
		///######## IF THE SESSION FILE EXISTS
		if(file_exists($SessionFile) === true){
			///######## UNLINK THE SESSION FILE
			unlink($SessionFile);
		}
    }
    


	///########-------------------------------------------------------------
	///########-------------------------------------------------------------
	///######## FUNCTION TO DELETE A SESSION FILE
	///########-------------------------------------------------------------
	///########-------------------------------------------------------------
	public static function GETCLASSVARS(){
        ///########==================================================
        ///######## SETUP RETURN DATA
        ///########==================================================
        $class      = new ReflectionClass('SESSION');
        $ReturnData = $class->getStaticProperties();
        ///########==================================================



        ///########==================================================
        ///######## RETURN THE RETURN DATA
        ///########==================================================
        return($ReturnData);
        ///########==================================================
    }



	///########-------------------------------------------------------------
	///########-------------------------------------------------------------
	///######## FUNCTION TO LOAD A CUSTOM CALLER ONLOAD
	///########-------------------------------------------------------------
	///########-------------------------------------------------------------
    private static function CustomCallerOnLoad(){
        ///########==================================================
        ///######## IF A CUSTOM CALLER FUNCTION HAS BEEN SET ON EXIT
        ///########==================================================
		if(isset(self::$CallerFunctions['onload']) === true){
			///######## SET THE FUNCTION TITLE
			$FunctionTitle = self::$CallerFunctions['onload'];

			///######## EXECUTE THE CUSTOM CALLER FUNCTION			
			if($FunctionTitle(self::$CurrentSession) === true){
				///########==================================================
				///######## DEFAULT RETURN TRUE
				///########==================================================
				return(true);
				///########==================================================
			}
			///######## IF NOT
			else{
				///########==================================================
				///######## RETURN DEFAULT FALSE
				///########==================================================
				return(false);
				///########==================================================
			}
		}
		///######## IF NOT
		else{
			///########==================================================
			///######## DEFAULT RETURN TRUE
			///########==================================================
			return(true);
			///########==================================================
		}
        ///########==================================================
	}
}
?>
