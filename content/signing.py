# Note that for testing, the files config.toml and backup.toml 
#    are written and read from the current dir, which is 
#    p = Path.home() / "Library/Gennaker/projects/Quick Start" / fname
# Comment out line 257 and uncomment the line above to undo this. 
# 

import platform 
from pathlib import Path
import shutil
import base64
from subprocess import run, CalledProcessError

from nacl.signing import SigningKey, VerifyKey
from nacl.exceptions import BadSignatureError

import tomli
import keyring
import requests

import ipywidgets as widgets
from IPython.display import display


class Messages:
    """
    Messages conveyed to user when they are managing keys.
    """

    def __init__(self):
        cfg = Config()
        bcfg = Config(backup=True) 
        
        if cfg.pf == "Darwin":
            keyapp = "Keychain Access"
            keyapp_dir = "/Applications/Keychain Access"
            if bcfg.kms == "keychain":
                old_location =  bcfg.kcn + " keychain"
            elif bcfg.kms == "filesystem":
                old_location = "Directory: " + bcfg.kdir 
            if cfg.kms == "keychain":
                current_location = cfg.kcn + " keychain"
            elif cfg.kms == "filesystem":
                current_location = "Directory: " + cfg.kdir 
                
        elif cfg.pf == "Windows":
            keyapp = "Windows Credentials"
            keyapp_dir = "Control Panel" 
            if bcfg.kms == "locker":
                old_location = "Credential Locker"
            elif bcfg.kms == "filesystem":
                old_location = "Directory: " + bcfg.kdir 
            if cfg.kms == "locker":
                current_location = "Credential Locker"
            elif cfg.kms == "filesystem":
                current_location = "Directory: " + cfg.kdir 
            
        self.dir_does_not_exist = f"""
            The directory {cfg.kdir} does not exist.
            
            If you keep your secret key on an external drive,
            make sure that the operating system can read 
            from this drive. 
            
            If the disk is connected by the directory {cfg.kdir} 
            does not exist, create it and try again. 
            
        """

        
        self.existing_same_loc = f"""
        You already have a secret Mainsail signing key in the location 
        specified in your current configuration: {current_location}. 

        To prevent the inadvertent loss of an existing key, no new key will be 
        created. The existing key is still there. 
        """

        self.remove_rerun = f"""
        If you want to stop using an existing key and generate and save 
        a new one: 

            i) Consider carefully whether you should rename the existing key
            or save a backup copy in a different location.

            ii) Remove or rename any key that includes the phrase 
            'mainsail_signing' in the location specified in your current 
            configuration.
            
            iii) Re-run the command that will generate and save a new key in 
            the location specified in your current configuration.
            
        For more information about your configuration and how to change 
        it, open the 'User Guide' project and look for the notebook on 
        configuration.


        To remove an existing Mainsail signing key from its
        current location: {current_location}
        
        If the current location is a directory, go to it and 
        rename or delete the file named 'mainsail_signing_key'.
        
        Otherwise, your key is stored in a location managed by 
        your operating system:
            
            i) Open the {keyapp} program. You can find it 
            in {keyapp_dir}.

            ii) Search for the phrase 'mainsail_signing'. 

            iii) Delete or rename any keys located by this
            search request. 

        """

        self.secret_moved = f"""
        You have a secret key stored in the location specified in a 
        backup copy of your config file:
        
            Old location: {old_location} 
                    
        You do not have a key stored in the current 
        location specified in your config file:

            Current location: {current_location}

        This problem can arise if you manually edit your config file
        without moving your key to the new location. 
        
        Because you should have a key stored in only one location, 
        the code has copied your secret to the current location and 
        has deleted it from the old location. 
        
        Now that the copy has taken place, try once more to run the 
        command that triggered this message.
        
        Also, to avoid this problem in the future, be sure to use the 
        "Configuration" notebook in the "User Guide" project to make. 
        You should run the code there to make any changes to your 
        configuration. It will move you secret if you your config 
        to specify a new location for your secret. 
        """


        self.move_secret_failed = f"""
        You have a secret key stored in the location specified in a 
        backup copy of your config file:
        
            Old location: {old_location} 

        You do not have a key stored in the current 
        location specified in your config file

            Current location: {current_location}

        This problem can arise if you manually edit your config file
        without moving your key to the new location. 
        
        Because you should have a key stored in only one location, 
        we have attempted to migrate your keys to the current location.

        Migration was NOT successful, and your old key remains at the old
        location. 
        
        This is possibly because you cancelled the password 
        dialog for a custom keychain. Rerun the code and enter the 
        correct password for your new location to migrate your keys.
        """


class Config:
    """A config holds basic info about the configuration of user machine.
    There are two types of config files: the current file and a backup
    file with the previous config. Every time there is a change to the
    config, the existing version should be saved to the backup. If the 
    new location for the secret string specified in the config 
    differs from location where the secret string is stored, it should 
    be moved to the new location. 
    
        Read from config.toml file if it exists; if not set to default 
        defined here. 
    On MacOS, the default keychain is called the 'login' keychain. It is 
        possible to create other keychains with their own passphrases. 
    On Windows, the 'Credential Locker' holds credentials. We use the term 
        'locker' in parallel with 'keychain'. Someone who is logged in can 
        use the Credential Manager API to access secrets stored 
        in the credential locker. 
    When a keypair writes to a location specified by the config, it saves 
        a copy as a backup config. 
    """
    def __init__(self, backup=False, c_default=False):
        self.backup = backup
        d = self.return_config_dict(backup, c_default)
        self.pf = platform.system()
        self.fmt = d["signature_format"]
        self.kms = d["key_management_strategy"]
        self.kcn = d["keychain_name"]
        self.kdir = d["key_dir"]
        self.floc =  d["folders_location"]
        self.trusted = self.trusted_keys_path()
        
        self.desktop_fdict = {
            "sin": Path.home() / "Desktop" / "to-sign",
            "sout": Path.home() / "Desktop" / "to-sign" / "signed",
            "vin": Path.home() / "Desktop" / "to-check",
            "qrt": Path.home() / "Desktop" / "to-check" / "quarantine",
            "vout": Path.home() / "Desktop" / "to-check" / "verified",
            "cout": Path.home() / "Desktop" / "to-check" / "checked",
            "sarch": Path.home() / "Desktop" / "to-check" / "checked" / "sig",
            "barch": Path.home() / "Desktop" / "to-check" / "checked" / "bundle",
        }

        self.documents_fdict = {
            "sin": Path.home() / "Documents" / "_digital_signatures" / "to-sign",
            "sout": Path.home() / "Documents" / "_digital_signatures" / "to-sign" / "signed",
            "vin": Path.home() / "Documents" / "_digital_signatures" / "to-check",
            "qrt": Path.home() / "Documents" / "_digital_signatures" / "to-check" / "quarantine",
            "vout": Path.home() / "Documents" /  "_digital_signatures" / "to-check" / "verified",
            "cout": Path.home() / "Documents" /  "_digital_signatures" / "to-check" / "checked",
            "sarch": Path.home() / "Documents" /  "_digital_signatures" / "to-check" / "checked" / "sig",
            "barch": Path.home() / "Documents" /  "_digital_signatures" / "to-check" / "checked" / "bundle",
        }

        if self.floc == "Desktop":
            self.fdict = self.desktop_fdict
            self.b_fdict  = self.documents_fdict # Possible folder location
        elif self.floc == "Documents":
            self.fdict = self.documents_fdict
            self.b_fdict = self.desktop_fdict
        #CHANGE
        self.create_or_move_folders()
    
    def create_or_move_folders(self) -> None:
        """Check if the input and output directories for auto-sign and auto-verify
        exist, if not, create the directories.
        """
        dne = False
        for k in self.fdict:
            if Path(self.fdict[k]).is_file():
                print("Error: {} is a file. Try again.".format(k))
                return False
            elif Path(self.fdict[k]).is_dir():
                continue
            elif not Path(self.fdict[k]).is_dir():
                # if folders exist in the other location, migrate, else create
                if self.b_fdict[k].is_dir():
                    shutil.move(self.b_fdict[k], self.fdict[k])
                    print("Moved directory: '{}'".format(
                        Path(self.fdict[k]).resolve())
                    )
                else:
                    Path(self.fdict[k]).mkdir(parents=True)
                    print("Created directory: '{}'".format(
                        Path(self.fdict[k]).resolve())
                    )
                dne = True
        if dne:
            #CHANGE: Only create symlink if document folders don't exist
            p = Path.home() / "Documents" /  "_digital_signatures"
            p_sym = Path.home() / "Desktop" / "digital_signatures"
            if self.floc == "Documents":
                if not p_sym.exists():
                    p_sym.symlink_to(
                        p, 
                        target_is_directory= True
                    )

            # Remove redundant symlink and folder
            elif self.floc == "Desktop":
                if p.is_dir():
                    p.rmdir()
                if p_sym.is_symlink():
                    p_sym.unlink()
    
    def return_config_dict(self, backup=False, c_default=False):
        """
        """
        default_macos = {
            'folders_location': 'Desktop',
            'signature_format': 'bundled',
            'key_management_strategy': 'keychain',
            'keychain_name': 'login',
            'key_dir': ''
        }
        default_windows = {
            'folders_location': 'Desktop',
            'signature_format': 'bundled',
            'key_management_strategy': 'locker',
            'keychain_name': '',
            'key_dir': ''
        }
        
        if platform.system() == "Darwin":
            default = default_macos
        elif platform.system() == "Windows":
            default = default_windows 
        
        if c_default:
            return default

        p = self.config_path(backup)
        
        if p.is_file():
            try:
                d = tomli.loads(p.read_text())
                if self.check_filesystem_kdir(d):
                    return d
                else:
                    self.config_path().unlink()
                    return default
            except:
                return default
        else:
            return default 

    @staticmethod
    def trusted_keys_path():
        if platform.system() == "Darwin":
            p = Path.home() / 'Library' / 'Gennaker' / 'config' / 'trusted_keys.txt'
        elif platform.system() == "Windows":
            p = Path.home() / 'AppData' / 'Local' / 'Gennaker'/ 'config' / 'trusted_keys.txt'
        return p

    @staticmethod
    def config_path(backup=False):
        if backup:
            fname = "backup.toml"
        else:
            fname = "config.toml"

        if platform.system() == "Darwin":
            p = Path.home() / 'Library' / 'Gennaker' / 'config' / fname
            # p = Path.home() / "Library/Gennaker/projects/Quick Start" / fname ###
        elif platform.system() == "Windows":
            p = Path.home() / 'AppData' / 'Local' / 'Gennaker'/ 'config' / fname 

        return p 

    def key_same_location(self, b):
        """Compares two configurations and looks for a difference 
        in the location for saving the secret key. tf signals 
        a boolean. Ignores irrelevant differences, e.g. 
        name for keychain if kms = 'locker'.
        """
        tf1 = self.kms == b.kms 
        tf2 = self.kms == "keychain" and self.kcn == b.kcn
        tf3 = self.kms == "locker"
        tf4 = self.kms == "filesystem" and self.kdir == b.kdir
        if tf1 and (tf2 or tf3 or tf4):
            return True
        else:
            return False

    @staticmethod
    def check_filesystem_kdir(d: dict)-> bool:
        """Check that kdir is not empty when using filesystem kms"""
        if d['key_management_strategy'] == "filesystem" and d['key_dir'] == "":
            print(f"    You are using 'filesystem' key management strategy without setting\n" 
                   "    a key directory. \n\n"
                   "    Set a valid 'key_dir' in config.toml.\n\n"
                   "    Using default config. The invalid config file has been removed."
            )
            return False
        else:
            return True
            
    def write_config(self, backup=False):
        """Write the values for the configuration to a text file 
        that will be readable as toml but which includes comments.
        To save a config, use backup=self.backup.
        To do a backup after a change, backup=True.
        """
        keys = [''] * 5
        keys[0] = 'folders_location =' 
        keys[1] = 'signature_format =' 
        keys[2] = 'key_management_strategy ='
        keys[3] = 'keychain_name ='
        keys[4] = 'key_dir ='

        values = [''] * 5
        values[0] = self.floc
        values[1] = self.fmt
        values[2] = self.kms
        values[3] = self.kcn
        values[4] = self.kdir

        comments = [''] * 5 
        comments[0] = "default = 'Desktop';  else 'Documents'"
        comments[1] = "default = 'bundled'; else 'separate'"
        comments[2] = "default = 'keychain' (Mac) or 'locker' (Win); else 'filesystem'"
        comments[3] = "default = 'login' (Mac) or '' (Win); else string"
        comments[4] = "default = ''; else string that translates to feasible path "

        s = ''
        for i in range(5):
            kv = keys[i] + ' ' + repr(values[i])
            s += f"{kv} \n" + ' ' * 4 + f"# {comments[i]}\n\n"

        p = self.config_path(backup)
        p.write_text(s)
        return 

    def delete_key(self):
        if self.kms == "keychain":
            self.del_from_keychain(self.kcn)
        elif self.kms == "locker":
            self.del_from_locker()
        elif self.kms == "filesystem":
            self.del_from_filesystem(self.kdir)
        
    @staticmethod
    def del_from_keychain(kcn) -> bool:
        """Delete secret key in keychain"""
        arg_list = [
            "security", "delete-generic-password",
            "-s", "mainsail_signing_service",
            "-a", "mainsail_secret_key",
            "-D", "ed25519_secret",
            kcn + ".keychain-db",
        ]
        try:
            run(arg_list, check=True, text=True, capture_output=True)
            return True
        except CalledProcessError as e:
            print(e.stderr)
            return False

    @staticmethod
    def del_from_locker():
        keyring.delete_password(
            "mainsail_secret_key", 
            "ed25519_secret", 
        )

    @staticmethod
    def del_from_filesystem(kdir):
        """Save a secret key to filesystem.
        """
        m = Messages()
        while not Path(kdir).is_dir():
            print(m.dir_does_not_exist)
            retry_usb = input("Enter 'y' to retry, any other key to cancel.")
            if retry_usb in ["y", "Y"]:
                print("Retrying ... ")
                continue 
            else:
                print("Canceling")
                return False

        (Path(kdir) / 'mainsail_signing_key.secret').unlink()


class Edsig:
    """Conversions between formats 
    Let b be a bytearray of any length
    Let b64 be a corresponding array encoded using base64

    Let M stand for either 44 or 88
        b_M is a bytearray of length M 
        s_M is a string of length M 
    Let n stand for either 32 or 64 
        b_n is a bytearray of length n 

    Hence, b64_M is a base64 encoded bytearray of length M 

    A key can be represented as 
        b_32: bytes len = 32 with default encoding
        b64_44: base64 encoded bytearray of len = 44 
        s_44: string len = 44

    A signature can be represented as 
        b_64: bytes len = 64 with default encoding 
        b64_88: base64 encoded bytesarray of len = 88
        s_88: string len = 88

    To convert, use:
        b_2_s: b_n to s_M
        s_2_b: s_M to b_n 

    """
    @staticmethod
    def bundle_suffix():
        return '.edbnl'
    
    @staticmethod
    def signature_suffix():
        return '.edsig'
    
    @staticmethod
    def s_2_b(s):
        return base64.urlsafe_b64decode(bytes(s, 'utf-8'))
        
    @staticmethod
    def b_2_s(b):
        return str(base64.urlsafe_b64encode(b), 'utf-8')

    @staticmethod
    def blk_2_sig(b: bytes)->str:
        """Reads a 315 byte block and returns a signature string."""
        blk = b[:315]
        s = str(blk, 'utf-8')
        sig = s[45:89] + s[90:134] 
        return sig
    
    @staticmethod
    def blk_2_ps(b: bytes)->str:
        """Reads a 315 byte block and returns a public string."""
        blk = b[:315]
        s = str(blk, 'utf-8')
        ps = s[225:269]
        return ps

    @staticmethod
    def bytes_2_msg(b: bytes) -> bytes:
        """Extract the msg bytes from a bundle"""
        return b[315:]
    
    @staticmethod 
    def sig_ps_2_blk(sig, ps):
        """Converts a sig string and public string to a 315 byte block."""
        s1 = ("BEGIN SIGNATURE".center(44, "-") + "\n"
            + sig[:44] + "\n"
            + sig[44:] + "\n"
            + "END SIGNATURE".center(44, "-") + "\n")
        s2 = ("BEGIN PUBLIC KEY FOR SIGNER".center(44, "-") + "\n"
            + ps + "\n"
            + "END PUBLIC KEY FOR SIGNER".center(44, "-") + "\n")
        return bytes(s1 + s2, 'utf-8')


class VerifyFiles(Edsig):
    """Takes key value arguments for the three file locations. 
    Accepts any one of them, or both p_doc and p_sig, which can then 
    be in different directories. 
    """
    def __init__(
        self, p_doc: Path = None, p_sig: Path = None, 
        p_bndl: Path = None
        ):
        if not p_bndl and not p_sig and not p_doc:
            print("Error: You need to supply at least one file path.")
            # return False 

            # problem: cannot return anything other than None from init
            # ^returning False also does not abort object instance initialization
            #REVIEW: As a special constraint on constructors, 
            # no value may be returned; doing so will cause a TypeError to be raised at runtime.
            # https://docs.python.org/3/reference/datamodel.html#object.__init__
        elif p_bndl and p_sig: 
            print("Error: Two locations for the signature file.")
            # return False
        elif p_bndl and p_doc: 
            print("Error: Two locations for the msg.")
            # return False

        self.p_doc = p_doc
        self.p_bndl = p_bndl
        self.p_sig = p_sig

        #CHANGE: set these attributes to None first so they all exist, 
        # catch the None in auto-verify
        self.sig = None
        self.ps = None
        self.msg = None

        # Read the values for verifying
        if self.p_bndl and self.p_bndl.is_file():
            b = self.p_bndl.read_bytes()
            self.sig = self.blk_2_sig(b)
            self.ps = self.blk_2_ps(b)
            self.msg = self.bytes_2_msg(b)
            self.p_doc = self.p_bndl.parent / (self.p_bndl.stem)
        else: 
            if self.p_doc and not self.p_sig:
                self.p_sig = Path(str(self.p_doc) + self.signature_suffix()) 
            elif self.p_sig and not self.p_doc:
                self.p_doc = self.p_sig.parent / (self.p_sig.stem)
            if self.p_sig.is_file():
                b = self.p_sig.read_bytes()
                self.sig = self.blk_2_sig(b)
                self.ps = self.blk_2_ps(b)
            else:
                print(f"The signature file does not exist at: {self.p_sig}\n")
                # return False
            if self.p_doc.is_file():
                self.msg = self.p_doc.read_bytes()
            else:
                print(f"The file does not exist at: {self.p_doc}\n")
                # return False
             

class SignFiles(Edsig):
    def write_bundle(self, p_doc, sig, ps, msg):
        b = self.sig_ps_2_blk(sig, ps) + msg
        p = Path(str(p_doc) + self.bundle_suffix()) 
        # print("p", p)
        p.write_bytes(b)
    
    def write_signature(self, p_doc, sig, ps):
        b = self.sig_ps_2_blk(sig, ps)
        p = Path(str(p_doc) + self.signature_suffix())
        p.write_bytes(b)


class ReadWriteStor(Edsig):
    """Methods that will be inherited by SecretObject.
    Some of these (e.g. save_key()) will not work if called from an instance such as  
    rws = ReadWriteStor() by using rws.save_key(). 
    """
    def read_secret(self):
        self.move_key()
        return self.return_string(backup=False, test=False)
        
    def read_secret_backup(self):
        self.move_key()
        return self.return_string(backup=True, test=False) 
        
    def test_secret(self):
        self.move_key()
        return self.return_string(backup=False, test=True)

    def test_secret_backup(self):
        self.move_key()
        return self.return_string(backup=True, test=True)
    
    def move_key(self):
        m = Messages()
        if not self.return_string(backup=False, test=True): 
            if self.return_string(backup=True, test=True): 
                if not Config().key_same_location(Config(backup=True)): 
                    self.write_string(self.return_string(backup=True, test=False))
                    if self.return_string(backup=False, test=True):
                        Config(backup=True).delete_key()
                        print(m.secret_moved)
                        Config().write_config(backup=True)
                    else:
                        print(m.move_secret_failed)
        return

    def return_string(self, backup, test):
        """Try to read the secret key. 
        If it exists and test=True, a return of True means 
        there is a secret key saved in this location.
        """
        c = Config(backup)
        if c.kms == "keychain":
            return self.from_keychain(c.kcn, test)
        elif c.kms == "locker":
            return self.from_locker(test)
        elif c.kms == "filesystem":
            return self.from_filesystem(c.kdir, test)

    @staticmethod
    def from_keychain(kcn, test=False):# -> str | bool:
        """Read secret string from keychain."""
        arg_list = [
                "security", "find-generic-password",
                "-w",
                "-s", "mainsail_signing_service",
                "-a", "mainsail_secret_key",
                kcn + ".keychain-db"
                ]
        try:
            cp = run(arg_list, check=True, text=True, capture_output=True)
            return cp.stdout.rstrip()
        except CalledProcessError as e:
            if e.returncode == 128:
                print(f"    The attempted read from the keychain '{kcn}' failed.")
                if not kcn == 'login':
                    print()
                    print("    You must unlock this keychain by supplying the password at the prompt or")
                    print("    by using the Keychain Access utility.")
                    print()
                    print(f"    If you have forgotten the password for the keychain '{kcn}', you may have to")
                    print("    create a new secret key and save it in a new location.")
                    print()
                else:
                    print()
                    print("    Use the Keychain Access utility to confirm whether there is a key in your")
                    print("    login keychain called mainsail_signing_key.")
                    print()
                    print("    If not, you may need to create a new signing key.")
                    print()
            elif not test:
                print("   ", e.stderr, "\n")
            return False

    @staticmethod 
    def from_locker(test=False):# -> str | bool:
        """Retrieve secret key string from Windows Credential Locker.
        Generate a new keypair from this string. Then you can read the public key 
        from the keypair."""
        key_str = keyring.get_password("mainsail_secret_key", "ed25519_secret")
        if not key_str:
            if not test:
                print(
                    "The key doesn't exist. If you haven't done so, "
                    "generate keys first."
                    "If you have lost your keys, generate a new key pair." 
                )
            return False
        else:
            if test:
                return True
            else:
                return key_str 

    @staticmethod 
    def from_filesystem(kdir, test=False):# -> str | bool:
        """Read plain text secret key from the filesystem."""
        while not Path(kdir).is_dir():
            print(Messages.dir_does_not_exist)
            retry_usb = input(
                "Enter 'y' or 'Y' to retry, anything else to cancel."
            )
            if retry_usb in ["y", "Y"]:
                print("Retrying ...")
                continue
            else:
                print("Canceled.")
                return False

        p = Path(kdir) / 'mainsail_signing_key.secret'
        if p.is_file():
            if test:
                return True
            else:
                return p.read_text()

    def save_key(self) -> bool:
        """Uses read to test, then uses write to save if ok.
        If save works, writes the config to backup.
        """
        m = Messages()
        self.move_key()
        if self.return_string(backup=False, test=True):
            print(m.existing_same_loc)
            print(m.remove_rerun)
            return False
        else: 
            self.write_string(self.b_2_s(bytes(self.secret_key))) # QUESTION
            if self.return_string(backup=False, test=True):
                Config().write_config(backup=True)

    def write_string(self, kss):# -> str | bool:
        c = Config()
        if c.kms == "keychain":
            self.to_keychain(c.kcn, kss)
        elif c.kms == "locker":
                self.to_locker(kss)
        elif c.kms == "filesystem":
            self.to_filesystem(c.kdir, kss)

    @staticmethod
    def to_keychain(kcn, kss):# -> str | bool:
        """Save a secret key string to keychain"""
        arg_list = [
            "security", "add-generic-password",
            "-s", "mainsail_signing_service",
            "-a", "mainsail_secret_key",
            "-D", "ed25519_secret",
            "-w", kss,
            kcn + ".keychain-db",
        ]
        try:
            run(arg_list, check=True, text=True, capture_output=True)
            return True
        except CalledProcessError as e:
            if e.returncode == 128:
                print(f"    The attempted write to the keychain '{kcn}' failed.")
                if not kcn == 'login':
                    print()
                    print("    You must unlock this keychain by supplying the password at the prompt or")
                    print("    by using the Keychain Access utility.")
                    print()
                    print(f"    If you have forgotten the password for the keychain '{kcn}', you may have to")
                    print("    create a new secret key and save it in a new location.")
                    print()
                else:
                    print("   ", e.stderr, "\n")
            else:
                print("   ", e.stderr, "\n")
            return False

    @staticmethod
    def to_locker(kss):# -> str | bool:
        """Save a secret key string to Windows Credential Locker.
        """
        keyring.set_password(
            "mainsail_secret_key", 
            "ed25519_secret", 
            kss,
        )
        return True

    @staticmethod
    def to_filesystem(kdir, kss):# -> str |bool:
        """Save a secret key to filesystem.
        """
        m = Messages()
        while not Path(kdir).is_dir():
            print(m.dir_does_not_exist)
            retry_usb = input("Enter 'y' to retry, any other key to cancel.")
            if retry_usb in ["y", "Y"]:
                print("Retrying ... ")
                continue 
            else:
                print("Canceling")
                return False

        (Path(kdir) / 'mainsail_signing_key.secret').write_text(kss)
        return True


class SecretObject(ReadWriteStor, SignFiles, Edsig):
    """
    A SecretObject depends on a seed and a config that determines 
    the location where the secret key_string will be saved.
    
    There are two ways to instantiate a SecretObject.
    
    1. Use random string of bytes as seed:
    - so = SecretObject.generate_key()
    
    2. Read in the string representation of the stored secret key:  
    - so = SecretObject.return_key()
    
    The attributes .__secret_string and .public_string are base64 string
        representations of the secret key and its public key. 
    """
    def __init__(self, string_seed):
        self.secret_key = SigningKey(self.s_2_b(string_seed))
        self.public_string = self.b_2_s(bytes(self.secret_key.verify_key))

    def __bytes__(self):
        """Returns the same bytes as the corresponding NaCl object."""
        return bytes(self.secret_key)

    @classmethod
    def generate_key(cls):
        return cls(cls.b_2_s(bytes(SigningKey.generate())))
    
    # Signing
    def sign(self, p_doc) -> str: 
        """Sign a file and write to a bundle or signature file."""

        if not p_doc.is_file():
            print("The specified file doesn't exist. Check the file path:")
            print("Path =", p_doc)
            return

        msg = p_doc.read_bytes()
        sig = self.b_2_s(self.secret_key.sign(msg).signature)
        ps = self.public_string 
        
        
        if Config().fmt == "bundled":
            self.write_bundle(p_doc, sig, ps, msg)
           
        elif Config().fmt == "separate":
            self.write_signature(p_doc, sig, ps)
    
        return True

    
class PublicObject(VerifyFiles, Edsig):
    def __init__(self, **kwargs):
        super().__init__(**kwargs)

    def __str__(self):
        """Returns the string from the corresponding NaCl object."""
        return self.public_string

    def __bytes__(self):
        """Returns the bytes from the corresponding NaCl object."""
        return self.s_2_b(self.public_string)
    

    def verify(self) -> bool:
        try:
            msg = VerifyKey(self.s_2_b(self.ps)).verify(self.msg, self.s_2_b(self.sig))
            # if self.p_bndl and self.p_bndl.is_file():
            #     self.p_doc.write_bytes(msg)
            return True
        except BadSignatureError:
            return False


class Authenticate():
    def __init__(self, verified_dir=None):
    
        t = self.scan_and_display(Path(verified_dir))

        self.l_vf = t[0]
        self.l_rdbns = t[1]

    def scan_and_display(self, verified_dir):
        
        l_vf = self.scan_for_files(verified_dir)

        # Create 2 lists of widgets
        l_doc_w = self.l_docname_html(l_vf)
        l_pf_b, l_pf_w = self.l_profile_html(l_vf)
        l_rdbns_w = self.rdbns(l_vf)
        
        # Disable widgets for rows where signer profile is not valid
        for i, b in enumerate(l_pf_b):
            if not b:
                l_rdbns_w[i].disabled=True

        self.confirm_button = widgets.Button(
            description='Click to confirm all choices',
            disabled=False,
            button_style='info', # 'success', 'info', 'warning', 'danger' or ''
            tooltip='Click me',
            icon='check', # (FontAwesome names without the `fa-` prefix)
            layout=widgets.Layout(
                width='max-content', 
                margin='1em',
            )
        )
        self.confirm_button.on_click(self.button_click)
        grid = self.table(l_doc_w, l_pf_w, l_rdbns_w)
        display(grid)
        btn_row = widgets.HBox(
            children=[self.confirm_button],
            layout=widgets.Layout(
                align_items='center',
                align_content='center',
                justify_content = 'center',
                width='100%',
            )
        )

        if len(l_vf) > 0:
            display(btn_row)
            # self.confirm_button.layout.visibility = "hidden"

        return (l_vf, l_rdbns_w)

    @staticmethod
    def scan_for_files(verified_dir=None) -> VerifyFiles:
        """Scan for edsig and edbnl files in destination folder. Only 
        look for edsig or edbnl, because only these contain public key"""
        
        l = list()
        if not verified_dir:
            verified_dir=Config().fdict["vout"]

        for p in verified_dir.iterdir():
            
            if p.suffix == ".edsig":
                vf = VerifyFiles(p_sig=p)
                l.append(vf)

            elif p.suffix == ".edbnl":
                vf = VerifyFiles(p_bndl=p)
                l.append(vf)

            else:
                continue
        return l

    @staticmethod
    def line_break_html(string):
        return '<br>'.join([string[i:i + 28] for i in range(0, len(string), 28)])

    def button_click(self, b):
        self.check_results()
        self.disable_widgets()

    def disable_widgets(self):
        for i in range(len(self.l_vf)):
            self.l_rdbns[i].disabled = True
        self.confirm_button.disabled = True
            
    def check_results(self):
        # Radio buttons: move files to folders 
        c = Config()
        for i, bns in enumerate(self.l_rdbns):

            vf = self.l_vf[i] # The corresponding vf obj

            # Move file to quarantine if verification is not successful
            if bns.value == "Do not trust sender":
                p_dst = c.fdict["qrt"]

            elif bns.value == "Trust only for current doc":
                p_dst = c.fdict["cout"]
            
            elif bns.value == "Add to trusted sender list":
                p_dst = c.fdict["cout"]

                #TODO: check duplicate public key?
                with c.trusted.open('a') as fp:
                    fp.write(vf.ps + "\n")
            
            if vf.p_bndl.is_file():
                shutil.move(vf.p_bndl, p_dst / vf.p_bndl.name)
                vf.p_doc.write_bytes(vf.msg) # REVIEW: file extraction moved here
            if vf.p_doc.is_file():
                shutil.move(vf.p_doc, p_dst / vf.p_doc.name) # REVIEW: depends at which step file is extracted
            elif vf.p_sig.is_file():
                shutil.move(vf.p_sig, p_dst / vf.p_sig.name)
            


    @staticmethod
    def xHTML(value):
        return widgets.HTML(
            value=value, 
            layout=widgets.Layout(height='auto', width='auto')
            # layout={'overflow-wrap': 'break-word', 'height':'auto', 'width':'auto'}
        )

    @staticmethod
    def title():
        return widgets.HTML(
            value='<h1 style="text-align: center">Authenticate Senders</h1>'
        )

    def l_docname_html(self, l_vf):
        """Create a list of HTML widgets for document names using the 
        list of VerifyFiles object, each of which has been instantiated 
        using a '.edsig' or '.edbnl' document in the input folder.
        """
        l = []
        for vf in l_vf:
            l.append(
                widgets.HTML(
                    value=f"<div style='word-break: break-all'>{vf.p_doc.name}</div>",
                    # value=
                        # f"""
                        # <div style='width: 50%; overflow: hidden; text-overflow: ellipsis; border: thin solid'> 
                        #     {vf.p_doc.name}
                        # </div>
                        # """,#font-size: 1rem;15rem
                    layout=widgets.Layout(height='auto', width='auto', margin="0 10px 0 0",)
                    # value=f"<div style='overflow: hidden; '>{vf.p_doc.name}</div>", #text-overflow: ellipsis;
                    # layout=widgets.Layout(height='auto', width='auto', border='solid')
                )
            )
        return l

    @staticmethod
    def fetch_profile_from_servers(vf):# -> tuple[bool, str]:
        """Find a member profile associated with a public key, if active 
        member profiles are found on > 2 of the servers, return (True, profile), 
        otherwise return (False, message)"""

        # create a url dictionary
        url_dict = {
            "AWS": "https://mainsail-s3-cli-test.s3.amazonaws.com/",
            "DO": "https://fra1.digitaloceanspaces.com/mainsail-do-cli-test/",
            "AZURE": "https://publickeyregistry.blob.core.windows.net/mainsail-az-cli-test/",
        }

        # Find the urls of member profile in all three services
        if vf.ps:
            for k in url_dict:
                url_dict[k] += vf.ps

        # Create a list to store profile dictionaries
        profiles = list()
        # Track the number of times a public key is inactive
        number_not_found = 0
        number_not_active = 0

        for k in url_dict:
            try:
                # Try accessing member profile page with public key URL
                r = requests.get(url_dict[k])
            except requests.exceptions.ConnectionError: 
                return (False, "Make sure your internet connection is working.")
                #DECIDE: we can't directly return None?
            
            # Internet connection works, see URL requests content
            # If access denied or URL does not exist, assume no Mainsail member found
            if r.status_code in [403, 404]: # AWS, DO return code 403, Azure 404
                number_not_found += 1 
        
            elif r.status_code == 200:
                try:
                    profile_dict = tomli.loads(r.text)
                #DECIDE: is this try except clause necessary? what's the possibility of having toml syntax error? can we avoid this if we check for this beforehand
                except tomli.TOMLDecodeError:
                    # If no Mainsail member associated with the public key is found
                    print("Problem parsing profile")
                else: # code that only executes if there's no exception
                    # Then check if profile is active
                    if not profile_dict["Public_key"]["Active"]:
                        number_not_active += 1 
                    elif len(profiles)== 0:
                        profiles.append(profile_dict)
        
        if number_not_found == 3:
            return (
                False, 
                "CHECK FAILED: No Mainsail member profile found associated with the public key."
            )

        elif number_not_found == 2:
            return (
                False,
                "CHECK FAILED: Problem with this member's profile..." # DECIDE: what to do in this case?
            )

        # If more than one inactive profile page found, return inactive
        elif number_not_active > 1:
            return (
                False,
                "CHECK FAILED: The member profile is inactive. "
                + "Please contact the member to obtain a file with an active key."
            )
        else:
            pf_d = profiles[0]
            # pf = (pf_d["Name"]["Value"] + "\n"
            #       + pf_d["Location"]["Value"] + "\n"
            #       + pf_d["Affiliation"]["Value"] + "\n"
            #       + "Last Verification Date:\n"
            #       + pf_d["Public_key"]["Last_verification_date"] + "\n")

            pf = f"""
                <div>
                    <p>{pf_d["Name"]["Value"]}</p>
                    <p>{pf_d["Location"]["Value"]}</p>
                    <p>{pf_d["Affiliation"]["Value"]}</p>
                    <p>Verified on {pf_d["Public_key"]["Last_verification_date"]}</p>
                </div>
                """
            return (True, pf)
    
    def l_profile_html(self, l_vf):
        """Create a list of HTML widgets for each profile fetching result 
        that correspond to a VerifyFiles object in the list,
        each of which correpsonds to a '.edsig' or '.edbnl' file
        """
        l_pf_b = list()
        l_pf_w = list()
        for i, vf in enumerate(l_vf):
            tuple = self.fetch_profile_from_servers(vf)
            l_pf_b.append(tuple[0])
            l_pf_w.append(self.xHTML(value=tuple[1]))
        l_pf_w.append(self.xHTML(value = ""))
        return l_pf_b, l_pf_w

    @staticmethod
    def rdbns(l_vf):
        """a bigger value for padding will shift the three buttons down"""
        l = []
        for i in range(len(l_vf)):
            l.append(
                widgets.RadioButtons(
                    options = ["Do not trust sender", 
                               "Trust only for current doc", 
                               "Add to trusted sender list"],
                    description = '',
                    layout = widgets.Layout(padding = '2em', height = 'auto', width = '26em'),
                    Description = "",
                    disabled = False))
        return l 
    
    @staticmethod
    def row_grids(l_doc_w, l_pf_w, l_rdbns_w):
        """A row grid allocates the space for the three elements in a row. 
        2/5 of length to doc and person, 1/5 to buttons"""
        l = []
        for i, d in enumerate(l_doc_w):
            rg = widgets.GridBox(
                children=[l_doc_w[i], l_pf_w[i], l_rdbns_w[i]],
                layout=widgets.Layout(
                    overflow='hidden',
                    width='100%',
                    height='auto',
                    grid_template_rows='auto', # 1 row of auto width
                    grid_template_columns='33.3% 33.3% 33.3%', # 4 columns
                )
            )
            l.append(rg)
        
        return l
            
    
    @staticmethod
    def hb(r_grid):
        return widgets.HBox((r_grid,), 
                    layout = widgets.Layout(border_top='thin solid', padding = '1em')
                )



    def col_grid(self, rg):
        col_grid = widgets.GridspecLayout(len(rg), 1)
        # col_grid.grid_gap='0em' 
        for j in range(len(rg)-1):
            col_grid[j,0] = self.hb(rg[j])
        col_grid[len(rg)-1,0] = widgets.HBox((rg[-1],),
                    layout = widgets.Layout(border_top='thin solid', 
                                    border_bottom='thin solid',
                                    padding = '1em',
                                    bottom_margin = '2em')
                                    )
        return col_grid


    def table(self, l_doc_w, l_pf_w, l_rdbns_w):
        return widgets.AppLayout(header = self.title(),
                        left_sidebar=None,
                        center=self.col_grid(
                            self.row_grids(l_doc_w, l_pf_w, l_rdbns_w)
                        ),
                        right_sidebar=None,
                        footer=None,
                        pane_heights = [1, 2, 0],
                        layout = widgets.Layout(margin = '2em')
                        )

# auto-sign
# when a file is dragged to "to-sign" folder
# sign and move to "signed" folder
# DECIDE: merge this with SecretObject or SignFiles?
# change the way write bundle or write signature is defined, so they share the same path attr?
#CHANGE
def auto_sign() -> None:
    """Sign all files with the format in Config, prepend the 
    signature, add suffix to the file. Move signed and unsigned file to
    the output directory."""
    c = Config()

    dir_in = c.fdict["sin"]
    dir_dst = c.fdict["sout"]

    dont_sign = [".DS_Store", ".ipynb_checkpoints"]

    so = SecretObject(ReadWriteStor().read_secret())
    if not so:
        print("Could not perform signing operation.")
    else:
        while True:

            for p_doc in dir_in.iterdir():

                if p_doc.is_file() and (p_doc.name not in dont_sign):
                    print("File to sign: ", p_doc.name, "\n")

                    so.sign(p_doc)

                    # Move the bundle or signature and the original 
                    # document to destination dir
                    if Config().fmt == "bundled":
                        p_signed = p_doc.parent / (p_doc.name + ".edbnl")
                    elif Config().fmt == "separate":
                        p_signed = p_doc.parent / (p_doc.name + ".edsig")

                    shutil.move(p_signed, dir_dst / p_signed.name)
                    shutil.move(p_doc, dir_dst / p_doc.name)
                        
                    print(
                        "The signed file and original file have been moved to: \n"
                        f"'{dir_dst}'\n", 
                        "---\n"
                    )

# auto-verify
# scan for all files in input dir, store in list
# test file ext, pass the corresponding kwarg based on ext to initialize PublicObject
# po.verify(), #DECIDE:method extracts file if bundle), catch the bool here
# check which output path exist, and move either p_doc and p_bndl or p_doc and p_sig
# move to quarantine if check failed, move to verified if check successful
#CHANGE
def auto_verify() -> None:
    """Scan for files in 'to-check' folder, if verification succeeds, move to 
    'verified' folder. If verification fails, move to 'quaratine' folder. 
    If signature or document is missing, prompt user to restart function.
    """
    c = Config()
    dir_in = c.fdict["vin"]

    # List of metadata files to be excluded and signed files that couldnt be verified
    cannot_verify = [".DS_Store", ".ipynb_checkpoints"]

    while True:
        # Filter out dirs and files that cannot be verified
        l_files = [
            p for p in dir_in.iterdir() if (
                not (p.name in cannot_verify)
                and p.is_file()
            )
        ]
        # Initialize Public Object with kwarg matching ext
        for p in l_files:
            if p.suffix == ".edbnl":
                print("Found a signed bundle: ", p.name, "\n")
                po = PublicObject(p_bndl=p)
            elif p.suffix == ".edsig":
                print("Found a signature: ", p.name, "\n")
                po = PublicObject(p_sig=p)
            else:
                print("Found a file: ", p.name, "\n")
                po = PublicObject(p_doc=p)

        # Check that PublicObject has been initialized with all needed attrs
            if not (po.sig and po.ps and po.msg): #CHANGE
                cannot_verify.append(p.name)
                print(
                    f"File '{p.name}' could not be verified.\n\n"
                    "Restart the function to verify this file again,"
                    "\n---"
                )
            else:
                if po.verify():
                    is_success = True
                    print("The file and signature have been verified\n")
                else:
                    is_success = False
                    print("The signature and file are not consistent.")
                    print("You should not trust the document.\n")
            
                # Move file
                # Check if verification was successful AND doc was extracted
                if is_success and po.p_doc.is_file():
                    p_dst = c.fdict["vout"]
                # Move file to quarantine if verification is not successful
                elif not is_success:
                    p_dst = c.fdict["qrt"]

                shutil.move(po.p_doc, p_dst / po.p_doc.name)
                if po.p_bndl:
                    shutil.move(po.p_bndl, p_dst / po.p_bndl.name)
                elif po.p_sig:
                    shutil.move(po.p_sig, p_dst / po.p_sig.name)

                print(
                    "The file has been moved to: ",
                    p_dst.parent,
                    "\n---",
                )


# ==== demo ====
def generate_and_save_key():
    SecretObject.generate_key().save_key()

def sign_file(p_doc: str):
    so = SecretObject(ReadWriteStor().read_secret())
    if so:
        so.sign(Path(p_doc))
    else:
        print("Could not perform signing operation.")

# Verify bundle
def verify_bundle(p_bundle: str):
    if Path(p_bundle).suffix == ".edbnl":
        po = PublicObject(p_bndl=Path(p_bundle))
        if not po:
            print("Could not perform verification operation.")
            return False
        else:
            if po.verify():
                print("The signature and message verify for the bundle:")
                print(po.p_bndl.resolve())
                print()
                # print("The document has been saved to:")
                # print(po.p_doc.resolve())
                return True
            else:
                print("The signature and file are not consistent.")
                print("You should not trust the document.")
                return False
 
    elif Path(p_bundle).suffix == ".edsig":
        print("This is the wrong file format for this function.")
        print("Use the verify_signatrue() function.")
        return False
    else:
        print("This is the wrong file format for this function.")
        print("Use the verify_document() function.")
        return False
        
