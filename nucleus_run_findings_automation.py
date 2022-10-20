import logging
import browser_cookie3
import requests

logging.basicConfig(filename='Nucleus_run_findings_rules.log', filemode='w',format='%(asctime)s - %(message)s', level=logging.INFO)

class NucleusInternal:
    """
    Nucleus Internal API Class
    """
    def __init__(self, domain, org_id):
        self.domain = domain
        self.base_url = f"https://{domain}"
        self.session = False
        self.cookie = None
        self.org_id = org_id

    def get_chrome_cookie(self):
        new_cj = {}
        try:
            cookiejar = browser_cookie3.edge()
            result = False
            self.cookie = {}
            for cookie in cookiejar:
                if cookie.domain == self.domain and cookie.name in ['PHPSESSID', 'csrfToken']:
                    self.session = True
                    self.cookie[cookie.name] = cookie.value
                    #self.cookie = self.format_cookie(new_cj)
            return self.cookie
        except Exception as error:
            return result, str(error)

    def get_finding_automation(self):
        full_url = f"{self.base_url}/nucleus/public/index.php/json/workflow?method=read&_dc=1666271883857&project_id=0&page=1&start=0&limit=25"
        findings = self.send_request(endpoint=full_url, method="GET",content_type="application/json")
        
        self.finds = findings
        return self.finds

    def run_finding_automation(self):
        params_list = []
        for x in self.finds:
            project_id = x['project_id']
            for sev in x['vuln_criteria']:
                severity = sev['display_value']
            for r in x['workflow_actions']:
                if "due_date" in r['action_type']:
                    action_type = r['action_type']
                    action_from = r['from']
                    action_offset = r['offset']
                    action_qualifier = r['qualifier']
                    action_display = f"Set {action_type}: {action_offset} {action_qualifier} from {action_from}"
                    
                    data = {
                    "workflow_criteria_asset_display":"",
                    "workflow_criteria_vuln_display":f"Severity:{severity}",
                    "workflow_actions_display":action_display,
                    "nonvalue":"non"}
                    
                    data.update(x)
                    logging.info(data)
                elif "assign" in  r['action_type']:
                    for t in x['asset_criteria']:
                        tag_name = t['rule_match_condition']
                        qualifier = t['rule_match_qualifier']
                        value = t['rule_match_value']
                    workflow_criteria_asset_display = f"{tag_name} {qualifier} {value}"
                    for w in x['workflow_actions']:
                        workflow_actions_display = w['assign_team_dynamic']

                    data = {
                    "workflow_criteria_asset_display":f"<span class=\"tag_field\" style=\"background:#919191;border-radius:4px;\">{workflow_criteria_asset_display}</span>",
                    "workflow_criteria_vuln_display":"",
                    "workflow_actions_display":f"Assign team dynamically with: {workflow_actions_display}",
                    "nonvalue":"non"}
                    data.update(x)
                    logging.info(data)



            params = {
                "project_id": project_id,
                "method":"runone",
                "changes": data,
                "csrfToken": self.cookie['csrfToken']

            }
            params_list.append(params)
        for params in params_list:
            full_url = f"{self.base_url}/nucleus/public/index.php/json/workflow"
            finding_rules = self.send_request(endpoint=full_url, method="POST", payload=params, content_type="application/x-www-form-urlencoded; charset=UTF-8")

    def send_request(self, endpoint, method, payload = None, content_type = None):
        headers = {
            'authority': self.domain,
            'accept': '*/*',
            'accept-language': 'en-US,en;q=0.9',
            'referer': f'{self.base_url}/nucleus/public/app/index.php',
            'sec-ch-ua': '"Chromium";v="106", "Microsoft Edge";v="106", "Not;A=Brand";v="99"',
            'sec-ch-ua-mobile': '?0',
            'sec-ch-ua-platform': '""Windows""',
            'sec-fetch-dest': 'empty',
            'sec-fetch-mode': 'cors',
            'sec-fetch-site': 'same-origin',
            'user-agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/106.0.0.0 Safari/537.36 Edg/106.0.1370.47',
            'x-requested-with': 'XMLHttpRequest',
        }
        if (method == "POST"):
            if "application/x-www-form-urlencoded" in content_type:
                headers['content-type'] = content_type
                response = requests.post(url=endpoint, verify= False, cookies=self.cookie, headers=headers, data=payload)
                r_status = str(response.status_code)
                print(r_status)
                name = payload['changes']['workflow_name']
                logging.info("sending payload for " + name + " status_code: " + r_status)
            else:
                response = requests.post(url=endpoint, verify=False, cookies=self.cookie, headers=headers, data=payload)
        else:
            #url = self.base + endpoint
            print('sending request')
            #queryArgs="method=read&_dc=1666271883857&project_id=0&page=1&start=0&limit=25"
            response = requests.get(url=endpoint, cookies=self.cookie, verify=False, headers=headers).json()
            print('got response')
        return response

if __name__ == "__main__":
    nucleus_internal_obj = NucleusInternal(domain="nucleus-us5.nucleussec.com", org_id=2)
    nucleus_internal_obj.get_chrome_cookie()
    finding_rules = nucleus_internal_obj.get_finding_automation()
    run_findings = nucleus_internal_obj.run_finding_automation()
