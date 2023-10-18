from log import log_message
from sf import SFExploit
from datetime import date
import argparse
import sys

def salesforce_tester(url:str, uri:str, token:str, sid:str, fwuid:str, app_data:str):
	log_message(f"> Testing: {url}")
	vulnerability = {'accessible_objects':[],
					'writable_objects':[]}
	got_objects = list()
	tester = SFExploit(url, uri, token, sid, fwuid, app_data)
	if tester.invalid:
		return {'vulnerable':False}
	available_objects = tester.get_objects()

	if (available_objects is not None):
		# test object access
		log_message(f">> Testing objects.")
		for object_name in available_objects:
			object_data = tester.get_object_items(object_name)
			if object_data: # something was returned:
				log_message(f">>> Found {object_name} to be accessible.")
				object_data_metric = {object_name:{'total_count':object_data['totalCount']}}
				vulnerability['accessible_objects'].append(object_data_metric)
				got_objects.append(object_name)

		# test write
		log_message(f">> Testing write to objects")
		for object_name in available_objects:
			write_allowed  = tester.attempt_record_create(object_name)
			if write_allowed:
				log_message(f">>> Found {object_name} to be potentially vulnerable.")
				vulnerability['writable_objects'].append(object_name)
	else:
		log_message(f">> No available objects.")
	
	if len(vulnerability['accessible_objects']) > 0 or len(vulnerability['writable_objects']) > 0:
		log_message(f">> Concluding testing for {url}. {url} is vulnerable.")
		final_return = {'vulnerable':True, 'data':vulnerability}
		return final_return
	else:
		log_message(f">> Concluding testing for {url}. {url} is not vulnerable")
		return {'vulnerable':False}

def main():
	parser = argparse.ArgumentParser(description="SRET - Salesforce Recon and Exploitation Toolkit")
	parser.add_argument('url', nargs='?')
	parser.add_argument('--token', type=str, required=False, dest='token', help = "AURA token (Authenticated user)")
	parser.add_argument('--sid', type=str, required=False, dest='sid', help = "SID cookie (Authenticated user)")
	parser.add_argument('--uri', type=str, required=False, dest='uri', help = "Force specific AURA endpoint URI")
	parser.add_argument('--fwuid', type=str, required=False, dest='fwuid', help = "Force specific FWUID (default: wrongfwuid))")
	parser.add_argument('--app', type=str, required=False, dest='app_data', help = "Force app (default: siteforce:loginApp2)")
	args = parser.parse_args()
	
	today = date.today()
	formatted_date = today.strftime("%m/%d/%Y")
	log_message(f"Scan date: {formatted_date}")
	vulnerable_or_not = salesforce_tester(args.url, args.uri, args.token, args.sid, args.fwuid, args.app_data)
	print(vulnerable_or_not)

main()