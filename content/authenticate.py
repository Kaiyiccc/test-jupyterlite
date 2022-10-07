from pathlib import Path
import shutil
import tomli
import requests
import ipywidgets as widgets

from IPython.display import display

from signing import VerifyFiles, Config

#TODO: do we need to add ipywigets to gpython?

# for loop scan for files, create list of vf, list of pf
# for loop create a list of radio btn and a list of checkbox widget
# display the widgets
# for loop check result with index of list of vf
# need to pass down lw, lw2, lvf. shallow copies?

# single authenticate objects, functions

class Authenticate():
    def __init__(self):
        t = self.scan_and_display()
        self.l_vf = t[0]
        self.l_rdbns = t[1]

    def scan_and_display(self):
        
        l_vf = self.scan_for_files()

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
    def scan_for_files() -> VerifyFiles:
        """Scan for edsig and edbnl files in destination folder. Only 
        look for edsig or edbnl, because only these contain public key"""
        
        l = list()

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
            
            if vf.p_doc.is_file():
                shutil.move(vf.p_doc, p_dst / vf.p_doc.name) # REVIEW: depends at which step file is extracted
            if vf.p_bndl:
                shutil.move(vf.p_bndl, p_dst / vf.p_bndl.name)
            elif vf.p_sig:
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
                    layout=widgets.Layout(height='auto', width='auto', margin="0 10px 0 0", border="thin solid")
                    # value=f"<div style='overflow: hidden; '>{vf.p_doc.name}</div>", #text-overflow: ellipsis;
                    # layout=widgets.Layout(height='auto', width='auto', border='solid')
                )
            )
        return l

    @staticmethod
    def fetch_profile_from_servers(vf) -> tuple[bool, str]:
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
                    grid_template_rows='auto', # 1 row of auto width
                    grid_template_columns='30% 40% 30%', # 4 columns
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
                        pane_heights = [1, 6, 0],
                        layout = widgets.Layout(margin = '2em')
                        )