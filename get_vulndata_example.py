import logging
import requests
import json
import os
from requests.adapters import HTTPAdapter
from urllib3.util import Retry
requests.packages.urllib3.disable_warnings()
from datetime import datetime, timedelta
import re
import pandas as pd
import http
from http.client import IncompleteRead

##### Logging
logging.basicConfig(filename='kenna_Nucleus_vulnreport.log', filemode='w',format='%(asctime)s - %(message)s', level=logging.INFO)

##### kenna API {project_id}/assessments

kenna_api_key = ""
kenna_headers = {"X-Risk-Token": kenna_api_key}
nucleus_token = ""
nucleus_user = ""

nucleus_api = "https://nucleus-us5.nucleussec.com/nucleus/api/projects/"

nucleus_project_search_api = "/findings/search"

nucleus_project_summary_api = "https://nucleus-us5.nucleussec.com/nucleus/api/projects/1000022/findings/summary"
nucleus_project_findDetails_api = "https://nucleus-us5.nucleussec.com/nucleus/api/projects/1000022/findings/details/"
nucleus_project_assetDetails_api = "/assets"
nucleus_project_scans = "https://nucleus-us5.nucleussec.com/nucleus/api/projects/1000022/scans/"


nucleus_project_severity_update_api = "https://nucleus-us5.nucleussec.com/nucleus/api/projects/1000022/findings"

nucleus_header = {"x-apikey": nucleus_token, 'content-type': 'application/json' }
nucleus_reports_header = {"x-apikey": nucleus_token, 'content-type': 'application/file' }
vulns = []
API_Host = os.environ.get("API_Host", "api.prod3.us.kennasecurity.com")


nucleus_dict = {}
nucleusReport_dict = {}
nucleusVulnReport_dict = {}
nucleusAsset_dict = {}
scan_dict = {}
proj_dict ={}

kenna_critical = []
kenna_high = []
kenna_med = []
kenna_low = []
asset_id_list =[]
ungrouped_asset = []
crit_vulns = []
high_vulns = []
med_vulns = []
low_vulns = []
info_vulns = []
scan_list = []
project_ids = []

def requests_retry_session(
    retries=3,
    backoff_factor=0.3,
    status_forcelist=(429, 500, 502, 504),
    session=None,
):
    session = session or requests.Session()
    retry = Retry(
        total=retries,
        read=retries,
        connect=retries,
        backoff_factor=backoff_factor,
        status_forcelist=status_forcelist,
    )
    adapter = HTTPAdapter(max_retries=retry)
    session.mount("http://", adapter)
    session.mount("https://", adapter)
    return session

def chunks(lst, n):
    for i in range(0, len(lst), n):
        yield lst[i : i + n]


def get_Nucleus_project_id():
    response=requests.get(nucleus_api, verify=False, headers={"x-apikey": nucleus_token, 'content-type': 'application/json'})
    r=response.json()
    print(r)
    for p in r:
        pid = p['project_id']
        pname= p['project_name']
        if 'Project' in pname:
            project_ids.append(pid)
            proj_item = {}
            proj_item = {'proj_name': pname, 'project_id': pid}
            proj_dict[pid] = proj_item
            scan_list.append(scan_dict)
        else:
            logging.info(pname + "Projects not in name")

def get_nucleus_asset_info():
    for proj_id in project_ids:
        x = proj_dict.get(proj_id)
        program = x['proj_name']
        p = re.search('(.+?) Project', program).group(1)
        page = 5000
        #page = 50
        start = 0
        params = {'limit': page, 'start': start}  

        pages_remaining = True
        full_res = []

        while pages_remaining:
            url = nucleus_api + proj_id + nucleus_project_assetDetails_api
            res = requests.get(url=url, verify=False, headers={"x-apikey": nucleus_token, 'content-type': 'application/json'}, params=params).json()
            start += 5000
            #start += 50
            params = {'limit': page, 'start': start, 'project_id': proj_id}
            #if len(res) <= 50:
            if not len(res) == 5000:
                pages_remaining = False
            for r in res:
                try:
                    asset_id = r['asset_id']
                    asset_name = r['asset_name']
                    ip_address = r['ip_address']
                    critical = r['finding_count_critical']
                    high = r['finding_count_high']
                    medium = r['finding_count_medium']
                    low = r['finding_count_low']
                    asset_groups = r['asset_groups']
                    asset_info = r['asset_info']
                    if asset_info:
                        tenable_uuid = r['asset_info']['tenable.uuid']
                        if not tenable_uuid:
                            tenable_uuid = "no_uuid"
                    else:
                        logging.info(asset_name + " has no uuid")
                    if not asset_groups:
                        asset_groups = "ungrouped"
                        ungrouped_asset.append(asset_id)
                    else:
                        pass
                    support_team = r['support_team']
                    if not support_team:
                        support_team = "noTeam"
                    else:
                        pass
                    nucleusReport_item = {
                    'Program': p,
                    'tenable_uuid': tenable_uuid,
                    'asset_id': asset_id,
                    'asset_name': asset_name,
                    'ip_address': ip_address,
                    'Critical': critical,
                    'High': high,
                    'Medium': medium,
                    'Low': low,
                    'asset_groups': asset_groups,
                    'project_id': proj_id,
                    'support_team': support_team
                    }
                    nucleusAsset_dict[asset_id] = nucleusReport_item
                    logging.info(nucleusReport_item)
                except Exception as e:
                    logging.info(e)
                    pass


# def get_asset_findings():
#     logging.info("Begin getting severity and cve")
#     for key in nucleusAsset_dict:
        
#         x = nucleusAsset_dict.get(key)
#         proj_id = project_id
#         try:
#             asset = key
#             uri2 = nucleus_project_assetDetails_api + "/" + key + "/findings"
#             params = {'project_id': proj_id, 'asset_id': asset} 
#             res2 = requests.get(url=uri2, verify=False, headers={"x-apikey": nucleus_token, 'content-type': 'application/json'}, params=params).json()
#             for re in res2:
#                 try:
#                     newItem = {}
#                     sev = re['finding_severity']
#                     cve = re['finding_cve']
#                     newItem = {
#                         'severity': sev,
#                         'cve': cve
#                     }
#                     newItem.update(x)
                
#                     logging.info(newItem)
#                     vulns.append(newItem)
    

            
#                 except Exception as e:
#                     logging.info(x)
#                     logging.info(e)
#         except Exception as e:
#                     logging.info(x)
#                     logging.info(e)

#     for a in vulns:

#         if 'Critical' in a['severity']:
#             crit_vulns.append(a)
#         elif 'High' in a['severity']:
#             high_vulns.append(a)
#         elif 'Medium' in a['severity']:
#             med_vulns.append(a)
#         elif 'Low' in a['severity']:
#             low_vulns.append(a)
#         elif 'Informational' in a['severity']:
#             info_vulns.append(a)

#     #logging.info(nucleusAsset_dict)

def get_asset_findings_search():
    logging.info("Begin getting severity and cve and scanID")

    for key in nucleusAsset_dict:
        x = nucleusAsset_dict.get(key)
        assetID = x['asset_id']
        project_id = x['project_id']
        proj_id = project_id
        page = 500
        #page = 10
        start = 0
        params = {'project_id': proj_id, 'limit': page, 'start': start}
        current_time = datetime.today() + timedelta(days=-7)
        scan_date = current_time.strftime('%Y-%m-%d %H:%M:%S')
        data = {
            "asset_id": assetID,
            "scan_date": {
                "operator": ">=",
                "datetime": scan_date
            }
            #[{"property":"scan_date_latest","operator":">=","value":"2022-09-22 08:28:37"}]
        } 
        pages_remaining = True
        full_res = []

        while pages_remaining:
            try:
                url = nucleus_api + proj_id + nucleus_project_search_api
                res = requests.post(url=url, verify=False, headers={"x-apikey": nucleus_token, 'content-type': 'application/json'}, params=params, json=data).json()
            except Exception as e:
                    logging.info("######### findings search error on post #######")
                    logging.info(e)
                    logging.info(key)
                    continue
            start += 500
            params = {'limit': page, 'start': start, 'project_id': project_id}
            if not len(res) == 500:
                pages_remaining = False
            for r in res:
                try:
                    sev = r['finding_severity']
                    cve = r['finding_cve']
                    scan_id = r['scan_id']
                    due_date = r['due_date']
                    finding_name = r['finding_name']
                    justification_has_file = r['justification_has_file']
                    justification_status_name = r['justification_status_name']
                    justification_assigned_teams = r['justification_assigned_teams']

                    newItem = {}
                    newItem = {
                        'severity': sev,
                        'cve': cve,
                        'scan_id': scan_id,
                        'due_date': due_date,
                        'finding_name': finding_name,
                        'justification_has_file': justification_has_file,
                        'justification_status_name': justification_status_name,
                        'justification_assigned_teams': justification_assigned_teams
                    }
                    scan_item = {}
                    scan_item = {'scan_id': scan_id, 'project_id': proj_id}
                    newItem.update(x)
                    scan_dict[scan_id] = scan_item
                    scan_list.append(scan_dict)


                    logging.info(newItem)
                    vulns.append(newItem)


            
                except Exception as e:
                    logging.info(x)
                    logging.info(e)

    
def get_asset_scan_file_name():
    logging.info("Begin getting scan file name")
    #s_list = list(dict.fromkeys(scan_list))
    for s in scan_dict:
        x = scan_dict.get(s)
    # for v in vulns:
        # scan_id = v['scan_id']
        scan_id = x['scan_id']
        project_id = x['project_id']
        try:
            uri3 = nucleus_project_scans + scan_id
            params = {'project_id': project_id, 'scan_id': scan_id} 
            res3 = requests.get(url=uri3, verify=False, headers={"x-apikey": nucleus_token, 'content-type': 'application/json'}, params=params).json()
            # for r in res3:
            try:
                scan_file_name = res3['scan_file_name']
                try:
                    p = re.search('-(.+?)~~', scan_file_name).group(1)
                    if p == 'tenableio-exports-tags-Program':
                        program = re.search('~~(.+?)-', scan_file_name).group(1)
                    else:
                        program = re.search('tags-(.+?)_', p).group(1)
                except AttributeError as a:
                    logging.info(a)
                    program = "None"
                    # AAA, ZZZ not found in the original string
                

                
                for v in vulns:
                    if s in v['scan_id']:
                        #v['scan_file_name'] = scan_file_name
                        v['Program'] = program
                    else:
                        continue
                #print(v)
                

            except Exception as e:
                logging.info(v)
                logging.info(e)
        except Exception as e:
                    logging.info(e)

    logging.info("Begin creating list of vulns")

def set_vuln_severity():
    for a in vulns:

        if 'Critical' in a['severity']:
            crit_vulns.append(a)
        elif 'High' in a['severity']:
            high_vulns.append(a)
        elif 'Medium' in a['severity']:
            med_vulns.append(a)
        elif 'Low' in a['severity']:
            low_vulns.append(a)
        elif 'Informational' in a['severity']:
            info_vulns.append(a)
    logging.info("END Search and  creating list of vulns")

def nucleusAssetdict_to_Excel():
    logging.info("Begin export to excel")
    
    writer = pd.ExcelWriter(('nuctest_last7days.xlsx'),engine='xlsxwriter')

    df = pd.DataFrame(vulns)
    df10 = df.drop(columns=['Critical', 'High', 'Medium', 'Low', 'support_team', 'asset_groups'])
    
    df1 = pd.DataFrame(crit_vulns)
    #df1.loc[:, ~df1.columns.isin(['finding_count_critical', 'finding_count_high', 'finding_count_medium', 'finding_count_low', 'support_team', 'asset_groups'])]
    df11 = df1.drop(columns=['Critical', 'High', 'Medium', 'Low', 'support_team', 'asset_groups'])
    
    df2 = pd.DataFrame(high_vulns)
    df12 = df2.drop(columns=['Critical', 'High', 'Medium', 'Low', 'support_team', 'asset_groups'])
    
    df3 = pd.DataFrame(med_vulns)
    df13 = df3.drop(columns=['Critical', 'High', 'Medium', 'Low', 'support_team', 'asset_groups'])
    
    df4 = pd.DataFrame(low_vulns)
    df14 = df4.drop(columns=['Critical', 'High', 'Medium', 'Low', 'support_team', 'asset_groups'])
    
    df5 = pd.DataFrame(info_vulns)
    df15 = df5.drop(columns=['Critical', 'High', 'Medium', 'Low', 'support_team', 'asset_groups'])
    
    df6 = df[['Program', 'Critical', 'High', 'Medium', 'Low']].copy()
    
    df7 = df6.drop_duplicates(subset=['Program'])
    
    df7.to_excel(writer, sheet_name='Summary', index = False)
    df10.to_excel(writer, sheet_name='All', index=False)
    df11.to_excel(writer, sheet_name='Critical', index=False)
    df12.to_excel(writer, sheet_name='High', index=False)
    df13.to_excel(writer, sheet_name='Medium', index=False)
    df14.to_excel(writer, sheet_name='Low', index=False)
    df15.to_excel(writer, sheet_name='Informational', index=False)
    writer.save()




if __name__ == "__main__":
    get_Nucleus_project_id()
    get_nucleus_asset_info()
    #get_asset_findings()
    
    get_asset_findings_search()
    #get_asset_scan_file_name()
    set_vuln_severity()
    nucleusAssetdict_to_Excel()

    with open('kenna_nucleus_integration_dict.json', 'w') as outfile:
        json.dump(nucleusReport_dict, outfile)
    


 
