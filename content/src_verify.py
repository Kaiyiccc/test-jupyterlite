# Note that for testing, the files config.toml and backup.toml 
#    are written and read from the current dir, which is 
#    p = Path.home() / "Library/Gennaker/projects/Quick Start" / fname
# Comment out line 257 and uncomment the line above to undo this. 
# 

from pathlib import Path
import base64

from cryptography.hazmat.primitives.asymmetric import ed25519
from cryptography.hazmat.primitives import serialization
from cryptography.exceptions import InvalidSignature

import tomli
import requests

import ipywidgets as widgets
from IPython.display import display

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
            msg = ed25519.Ed25519PublicKey.from_public_bytes(self.s_2_b(self.ps)).verify(self.s_2_b(self.sig), self.msg)
            # if self.p_bndl and self.p_bndl.is_file():
            #     self.p_doc.write_bytes(msg)
            return True
        except InvalidSignature:
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
            verified_dir=Path("./")

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
        for i, bns in enumerate(self.l_rdbns):

            vf = self.l_vf[i] # The corresponding vf obj

            # Move file to quarantine if verification is not successful
            if bns.value == "Do not trust sender":
                print("Do not trust sender")
            elif bns.value == "Trust only for current doc":
                print("Trust only for current doc")
            
            elif bns.value == "Add to trusted sender list":
                print("Add to trusted sender list")
            


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

# auto-verify
# scan for all files in input dir, store in list
# test file ext, pass the corresponding kwarg based on ext to initialize PublicObject
# po.verify(), #DECIDE:method extracts file if bundle), catch the bool here
# check which output path exist, and move either p_doc and p_bndl or p_doc and p_sig
# move to quarantine if check failed, move to verified if check successful
#CHANGE

# ==== demo ====

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
        
