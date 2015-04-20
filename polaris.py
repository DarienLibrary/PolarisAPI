from email.utils import formatdate
from hashlib import sha1
import hmac
import json
import requests
from time import time

class PAPI(object):
	'''
	A Python interface into the Polaris API

	Example usage:

	>>> import polaris
	>>> papi = polaris.PAPI('YOUR-POLARIS-API-ACCESS-KEY','yourapiuser','your.library.hostname')
	
	All methods return a requests library Response object.
	To get bibliographic information associated with bibID, '353063':

	>>> resp = papi.bibGet('353063')
	>>> print resp.json()

	All method descriptions are derived from the original language present in
	the Polaris Application Programming Interface (PAPI) Reference Guide.
	Every method makes requests with the following defaults unless keyword
	arguments are otherwise provided in the function call:

		version='v1'
		langID='1033'	#English
		appID='100'	#third-party
		orgID='1'	#system level

	Each method requires all arguments marked as required in the Polaris
	Application Programming Interface (PAPI) Reference Guide. Any additional
	arguments may be passed as keyword arguments in which the keyword is the
	name provided in the Polaris Application Programming Interface (PAPI)
	Reference Guide though in some cases altered to conform with camelCase.
	(eg. org_ID becomes orgID)

	Note about query sting parameters:
	With the exception of holdRequestCancel, holdRequestCancelAllForPatron,
	patronAccountPay and patronReadingHistoryGet (for which all two of the
	query string parameters are simply required as function arguments), all
	methods which use query sting parameters expect a dictionary, params,
	containing keyword-value pairs in which the keyword is the name provided
	in the Polaris Application Programming Interface (PAPI) Reference Guide
	under Query String Parameters for that method.
 	
 	For example:
 	>>> papi.headingSearch(qualifierName='su',params={'startpoint':'civil war','numterms':'10'})
 	(N.B. the values provided in params are NOT URL encoded.)

	Use of protected methods:
	see authenticateStaffUser

	Use of patron password override:
	Any patron method can be overriden by an authenticated staff user by
	providing an access secret in place of the patron password and passing the
	associated access token as a keyword argument as in the following example.
	>>> papi.patronBasicDataGet(patronBarcode='patronbarcode',patronPassword='accesssecret',accessToken='accesstoken')

	Note on activation date:
	All functions requiring activationDate expect the date to be supplied as a
	string representation of the integer value of seconds since Epoch Time.
	'''

	def __init__(self,accessKey,accessKeyID,hostname):
		self._accessKey = accessKey
		self._accessKeyID = accessKeyID
		self._hostname = hostname
		self._session = requests.Session()

	def _getPAPIHash(self,HTTPMethod,URI,HTTPDate,patronPassword):
		message = HTTPMethod + URI + HTTPDate + patronPassword
		print message
		hashed = hmac.new(self._accessKey,message,sha1)
		return hashed.digest().encode('base64')[:-1]

	def _dictParse(self,params):
		# Despite the requests library handling URL encoding in the 
		# construction of a request, I could only consistently pass server 
		# authetication requirements by parsing query string parameters as
		# follows and then manually appending them.
		parsedParams = ''
		for paramKey in params.keys():
			parsedParamKey = ''
			for char in paramKey:
				if char == ' ': parsedParamKey += '+'
				else: parsedParamKey += char
			parsedParamValue = ''
			for char in params[paramKey]:
				if char == ' ': parsedParamValue += '+'
				else: parsedParamValue += char
			parsedParams += '&'+parsedParamKey+'='+parsedParamValue
		if parsedParams: return '?'+parsedParams[1:]
		return parsedParams

	def _undifferentiatied(self,protocol,HTTPMethod,protection,suffixURI,**kwargs):
		# This is the heart of the API wrapper. All the Polaris API methods
		# take their method specific input and parse it and call this method
		# which then constructs and sends the appropriate request.
		version = kwargs.get('version','v1')
		langID = kwargs.get('langID','1033')
		appID = kwargs.get('appID','100')
		orgID = kwargs.get('orgID','1')
		paramsSuffix = self._dictParse(kwargs.get('params',{}))
		data = json.dumps(kwargs.get('data',{}))
		patronPassword = kwargs.get('accessSecret',kwargs.get('patronPassword',''))
		accessToken = kwargs.get('accessToken','')

		rootURI = '{protocol}://{hostname}/PAPIService/REST/{protection}/{version}/{langID}/{appID}/{orgID}/'.format(protocol=protocol,hostname=self._hostname,protection=protection,version=version,langID=langID,appID=appID,orgID=orgID)
		URI = rootURI+suffixURI+paramsSuffix
		req = requests.Request(HTTPMethod,URI,data=data)
		preparedRequest = req.prepare()
		HTTPDate = formatdate(timeval=None, localtime=False, usegmt=True)
		signature = self._getPAPIHash(HTTPMethod,preparedRequest.url,HTTPDate,patronPassword)
		print signature
		headers = {	'Authorization':'PWS {accessKeyID}:{signature}'.format(accessKeyID=self._accessKeyID,signature=signature),
					'Date':HTTPDate,
					'Content-Type':'application/json',
					'Content-Length':len(data),
					'Accept':'application/json'}
		if accessToken and protection=='public': headers.update({'X-PAPI-AccessToken':accessToken})
		preparedRequest.headers = headers
		return self._session.send(preparedRequest)

	def authenticateStaffUser(self,domain,username,password,**kwargs):
		'''
			A call to authenticateStaffUser is required before calling any 
			protected methods. Upon success, this method will return an access
			token and access secret. These will be used to create the hash for
			protected methods. The access token is valid for 24 hours. 
			Subsequent calls to authenticateStaffUser with the same domain
			account information will generate a new access token, access
			secret and expiration date.

			Example:
			>>> papi.authenticateStaffUser(domain='yourdomain',username='yourusername',password='yourpassword')
		'''
		protocol = 'https'
		HTTPMethod = 'POST'
		protection = 'protected'
		suffixURI = 'authenticator/staff'
		data = {'Domain':domain,
				'Username':username,
				'Password':password}
		return self._undifferentiatied(protocol,HTTPMethod,protection,suffixURI,data=data,**kwargs)

	def bibGet(self,bibID,**kwargs):
		'''	Returns bibliographic information for a specified record.

			Example:
			>>> papi.bibGet(bibID='353063')
		'''
		protocol = 'http'
		HTTPMethod = 'GET'
		protection = 'public'
		suffixURI = 'bib/{bibID}'.format(bibID=bibID)
		return self._undifferentiatied(protocol,HTTPMethod,protection,suffixURI,**kwargs)

	def bibSearch(self,qualifierName,params,**kwargs):
		'''
			Returns list of bibliographic records that match search criteria.
			For boolean searches, you may opt to include the SORTBY clause
			when using the q query string parameter. This returns search
			results sorted in the specified sort order. 

			Example:
			>>> papi.bibSearch(qualifierName='bc',params={'q':'32491015192050'})
		'''
		protocol = 'http'
		HTTPMethod = 'GET'
		protection = 'public'
		suffixURI = 'search/bibs/keyword/{qualifierName}'.format(qualifierName=qualifierName)
		return self._undifferentiatied(protocol,HTTPMethod,protection,suffixURI,params=params,**kwargs)

	def headingSearch(self,qualifierName,params,**kwargs):
		'''
			Searches an ordered list of terms and returns headings information 
			relative to a given start point.

			Example:
			>>> papi.headingSearch(qualifierName='su',params={'startpoint':'civil war','numterms':'10'})
		'''
		protocol = 'http'
		HTTPMethod = 'GET'
		protection = 'public'
		suffixURI = 'search/headings/{qualifierName}'.format(qualifierName=qualifierName)
		return self._undifferentiatied(protocol,HTTPMethod,protection,suffixURI,params=params,**kwargs)

	def collectionsGet(self,**kwargs):
		'''
			Returns a list of collections based on the organization ID (passed
			as the keywoard argument orgID, otherwise defaults to '1').
			Branches utilize a subset of collection information maintained at
			the system level in Polarisself.To retrieve a list of all
			collections in the system, call without any arguments. To retrieve
			a list of collections for a specific branch, pass the branch ID.

			Example:
			>>> papi.collectionsGet(orgID='2')
		'''
		protocol = 'http'
		HTTPMethod = 'GET'
		protection = 'public'
		suffixURI = 'collections'
		return self._undifferentiatied(protocol,HTTPMethod,protection,suffixURI,**kwargs)

	def bibHoldingsGet(self,bibID,**kwargs):
		'''
			Returns holdings information for a specified bibliographic record.

			Example:
			>>> papi.bibHoldingsGet(bibID='353063')
		'''
		protocol = 'http'
		HTTPMethod = 'GET'
		protection = 'public'
		suffixURI = 'bib/{bibID}/holdings'.format(bibID=bibID)
		return self._undifferentiatied(protocol,HTTPMethod,protection,suffixURI,**kwargs)

	def holdRequestCancel(self,patronBarcode,patronPassword,requestID,workstationID,userID,**kwargs):
		'''
			Cancel a single hold request.

			Example:
			>>> papi.holdRequestCancel(patronBarcode='patronbarcode',patronPassword='patronpassword',requestID='311260',workstationID='1',userID='2')
		'''
		protocol = 'http'
		HTTPMethod = 'PUT'
		protection = 'public'
		params={'wsid':workstationID,
				'userid':userID}
		suffixURI = 'patron/{patronBarcode}/holdrequests/{requestID}/cancelled'.format(patronBarcode=patronBarcode,requestID=requestID)
		return self._undifferentiatied(protocol,HTTPMethod,protection,suffixURI,patronPassword=patronPassword,params=params,**kwargs)

	def holdRequestCancelAllForPatron(self,patronBarcode,patronPassword,workstationID,userID,**kwargs):
		'''
			Cancel all local hold requests for a specific patron whose hold
			requests have a status of inactive (1), active (2) or pending (4).

			Example:
			>>> papi.holdRequestCancelAllForPatron(patronBarcode='patronbarcode',patronPassword='patronpassword',workstationID='1',userID='2')
		'''
		return self.holdRequestCancel(patronBarcode,patronPassword,0,workstationID,userID,**kwargs)

	def holdRequestCreate(self,patronID,bibID,pickupOrgID,workstationID,userID,requestingOrgID,**kwargs):
		'''
			Start the local hold request process. This process is based on a
			"messaging" system and will allow a Polaris patron to place a
			local hold request. After calling the HoldRequestCreate method,
			one or more calls to the HoldRequestReply method may be required.
			The message exchange is complete when a StatusType of Error (1) or
			Answer (2) is returned or if an error is raised via a database
			exception. Uses current time if ActivationDate is not supplied.

			Example:
			>>> papi.holdRequestCreate(patronID='121175',bibID='353063',pickupOrgID='3',workstationID='1',userID='2',requestingOrgID='3')
		'''
		protocol = 'http'
		HTTPMethod = 'POST'
		protection = 'public'
		suffixURI = 'holdrequest'
		data = {'PatronID':patronID,
				'BibID':bibID,
				'ItemBarcode':kwargs.get('itemBarcode',''),
				'VolumeNumber':kwargs.get('volumeNumber',''),
				'Designation':kwargs.get('designation',''),
				'PickupOrgID':pickupOrgID,
				'IsBorrowByMail':kwargs.get('isBorrowByMail','0'),
				'PatronNotes':kwargs.get('patronNotes',''),
				'Answer':kwargs.get('answer',None),
				'ActivationDate':'/Date({timestamp}000-0000)/'.format(timestamp=kwargs.get('activationDate',str(int(time())))),
				'UserID':userID,
				'RequestingOrgID':requestingOrgID,
				'TargetGUID':kwargs.get('targetGUID','')}
		return self._undifferentiatied(protocol,HTTPMethod,protection,suffixURI,data=data,**kwargs)

	def holdRequestReply(self,requestGUID,txnGroupQualifier,txnQualifier,requestingOrgID,answer,state,**kwargs):
		'''
			Send a reply message responding to the results of a previous
			HoldRequestCreate or HoldRequestReply procedure call. The 
			HoldRequestCreate procedure must be called before executing this
			procedure. The RequestGUID, TxnGroupQualifier and TxnQualifier
			returned by the HoldRequestCreate procedure will be used as input
			parameters for this procedure call. These three values connect the
			messages together to create an ILL conversation. After calling the
			HoldRequestReply procedure, one or more calls to the 
			HoldRequestReply procedure may be required. The message exchange
			is complete when a StatusType of Error (1) or Answer (2) is
			returned or if an error is raised via a database exception.

			Example:
			>>> papi.holdRequestReply(requestGUID='6297419E-57C1-460B-9A84-BC4A04B3F715',txnGroupQualifier='sIeGLBBJaKEtHvRFoXq3pa',txnQualifier='1al_YfH4ge6$nbiJ7pNaXW',requestingOrgID='3',answer='0',state='3')

		'''
		protocol = 'http'
		HTTPMethod = 'PUT'
		protection = 'public'
		suffixURI = 'holdrequest/{requestGUID}'.format(requestGUID=requestGUID)
		data = {'TxnGroupQualifier':txnGroupQualifier,
				'TxnQualifier':txnQualifier,
				'RequestingOrgID':requestingOrgID,
				'Answer':answer,
				'State':state}
		return self._undifferentiatied(protocol,HTTPMethod,protection,suffixURI,data=data,**kwargs)

	def holdRequestSuspend(self,patronBarcode,patronPassword,requestID,activity,userID,activationDate,**kwargs):
		'''
			Suspend or reactivate a single hold request.

			Example:
			>>> papi.holdRequestSuspend(patronBarcode='patronbarcode',patronPassword='patronpassword',requestID='311608',activity='active',userID='1',activationDate='1491058000000')
		'''
		protocol = 'http'
		HTTPMethod = 'PUT'
		protection = 'public'
		suffixURI = 'patron/{patronBarcode}/holdrequests/{requestID}/{activity}'.format(patronBarcode=patronBarcode,requestID=requestID,activity=activity)
		data = {'UserID':userID,
				'ActivationDate':'/Date({timestamp}000-0000)/'.format(timestamp=activationDate)}
		return self._undifferentiatied(protocol,HTTPMethod,protection,suffixURI,patronPassword=patronPassword,data=data,**kwargs)

	def holdRequestSuspendAllForPatron(self,patronBarcode,patronPassword,activity,userID,**kwargs):
		'''
			Suspend or reactivate all local hold requests for a specific
			patron whose hold requests have a status of inactive (1),
			active (2) or pending (4).

			Example:
			>>> papi.holdRequestSuspendAllForPatron(patronBarcode=PATRONBARCODE,patronPassword=PATRONPASSWORD,activity='active',userID='1',activationDate='1491058000000')
		'''
		return self.holdRequestSuspend(patronBarcode,patronPassword,'0',activity,userID,**kwargs)

	def itemRenew(self,patronBarcode,patronPassword,itemID,logonBranchID,logonUserID,logonWorkstationID,ignoreOverrideErrors,**kwargs):
		'''
			Attempt to renew an item that is already checked out.

			Example:
			>>> papi.itemRenew(patronBarcode='patronbarcode',patronPassword='patronpassword',itemID='311608',logonBranchID='3',logonUserID='2',logonWorkstationID='1',ignoreOverrideErrors='true')
		'''
		protocol = 'http'
		HTTPMethod = 'PUT'
		protection = 'public'
		suffixURI = 'patron/{patronBarcode}/itemsout/{itemID}'.format(patronBarcode=patronBarcode,itemID=itemID)
		data = {'Action':'renew',
				'LogonBranchID':logonBranchID,
				'LogonUserID':logonUserID,
				'LogonWorkstationID':logonWorkstationID,
				'RenewData':{'IgnoreOverrideErrors':ignoreOverrideErrors}}
		return self._undifferentiatied(protocol,HTTPMethod,protection,suffixURI,patronPassword=patronPassword,data=data,**kwargs)
	
	def itemRenewAllForPatron(self,patronBarcode,patronPassword,logonBranchID,logonUserID,logonWorkstationID,ignoreOverrideErrors,**kwargs):
		'''
			Attempt to renew all items currently out to a patron.

			Example:
			>>> papi.itemRenew(patronBarcode='patronbarcode',patronPassword='patronpassword',logonBranchID='3',logonUserID='2',logonWorkstationID='1',ignoreOverrideErrors='true')
		'''
		return self.itemRenew(self,patronBarcode,patronPassword,0,logonBranchID,logonUserID,logonWorkstationID,ignoreOverrideErrors,**kwargs)

	def limitFiltersGet(self,**kwargs):
		'''
			Returns list of valid bib search limit filters based on the
			organization's Polaris System Administration values.

			Example:
			>>> papi.limitFiltersGet()
		'''
		protocol = 'http'
		HTTPMethod = 'GET'
		protection = 'public'
		suffixURI = 'limitfilters'
		return self._undifferentiatied(protocol,HTTPMethod,protection,suffixURI,**kwargs)

	def notificationUpdate(self,accessToken,accessSecret,notificationTypeID,logonBranchID,logonUserID,logonWorkstationID,notificationStatusID,notificationDeliveryDate,deliveryOptionID,deliveryString,patronID,patronLanguageID,**kwargs):
		'''
			The NotificationUpdate method will update the Notification Log and
			remove or update the Notification Queue entry. It is also
			responsible for updating related ItemCheckout data elements and
			rolling phone notification into print notification. This method
			should be called after a patron is contacted.
			
			This method only supports telephone notification processing and
			may be used in conjunction with the phone notification export
			process.

			Example:
			>>> papi.notificationUpdate(accessToken='accesstoken',accessSecret='accesssecret',notificationTypeID='3',logonBranchID='3',logonUserID='2',logonWorkstationID='1',notificationStatusID='1',notificationDeliveryDate='/Date(1391058000000-0500)/',deliveryOptionID='3',deliveryString='4237570576',patronID='121175',patronLanguageID='1033',itemRecordID='353063',reportingOrgID='3')
		'''
		#UNABLE TO TEST
		protocol = 'http'
		HTTPMethod = 'PUT'
		protection = 'protected'
		suffixURI = '{accessToken}/notification/{notificationTypeID}'.format(accessToken=accessToken,notificationTypeID=notificationTypeID)
		data = {'LogonBranchID':logonBranchID,
				'LogonUserID':logonUserID,
				'LogonWorkstationID':logonWorkstationID,
				'ReportingOrgID':kwargs.get('reportingOrgID',None),
				'NotificationStatusID':notificationStatusID,
				'NotificationDeliveryDate':notificationDeliveryDate,
				'DeliveryOptionID':deliveryOptionID,
				'DeliveryString':deliveryString,
				'Details':kwargs.get('details',None),
				'PatronID':patronID,
				'PatronLanguageID':patronLanguageID,
				'ItemRecordID':kwargs.get('itemRecordID',None)}
		return self._undifferentiatied(protocol,HTTPMethod,protection,suffixURI,accessSecret=accessSecret,data=data,**kwargs)

	def organizationsGet(self,tier,**kwargs):
		'''
			Returns list of system, library and branch level organizations.
			The list can be filtered by system, library or branch.

			Example:
			>>> papi.organizationsGet('all')
		'''
		protocol = 'http'
		HTTPMethod = 'GET'
		protection = 'public'
		suffixURI = 'organizations/{tier}'.format(tier=tier)
		return self._undifferentiatied(protocol,HTTPMethod,protection,suffixURI,**kwargs)

	def patronAccountGet(self,patronBarcode,patronPassword,status,**kwargs):
		'''
			Returns list of fines and fees associated with a specified patron.
			The list can be filtered by outstanding (current) or reconciled
			(historical) fines and fees.

			Example:
			>>> papi.patronAccountGet(patronBarcode='patronbarcode',patronPassword='patronpassword',status='reconciled')
		'''
		protocol = 'http'
		HTTPMethod = 'GET'
		protection = 'public'
		suffixURI = 'patron/{patronBarcode}/account/{status}'.format(patronBarcode=patronBarcode,status=status)
		return self._undifferentiatied(protocol,HTTPMethod,protection,suffixURI,patronPassword=patronPassword,**kwargs)

	def patronAccountPay(self,accessToken,accessSecret,patronBarcode,chargeTxnID,txnAmount,paymentMethodID,workstationID,userID,**kwargs):
		'''
			Makes a payment on an existing charge on the Polaris patron
			account.

			Example:
			>>> papi.patronAccountPay(accessToken='accesstoken',accessSecret='accesssecret',patronBarcode='patronbarcode',chargeTxnID='1170113',txnAmount='0',paymentMethodID='11',workstationID='1',userID='2')
		'''
		protocol = 'https'
		HTTPMethod = 'PUT'
		protection = 'protected'
		suffixURI = '{accessToken}/patron/{patronBarcode}/account/{chargeTxnID}/pay'.format(accessToken=accessToken,patronBarcode=patronBarcode,chargeTxnID=chargeTxnID)
		data = {'TxnAmount':txnAmount,
				'PaymentMethodID':paymentMethodID,
				'FreeTextNote':kwargs.get('freeTextNote',None)}
		params={'wsid':workstationID,
				'userid':userID}
		return self._undifferentiatied(protocol,HTTPMethod,protection,suffixURI,accessSecret=accessSecret,data=data,params=params,**kwargs)

	def patronBasicDataGet(self,patronBarcode,patronPassword,**kwargs):
		'''
			Return basic name, address, circulation counts, and account
			balances for a patron.

			Example:
			>>> papi.patronBasicDataGet(patronBarcode='patronbarcode',patronPassword='patronpassword')
		'''
		protocol = 'http'
		HTTPMethod = 'GET'
		protection = 'public'
		suffixURI = 'patron/{patronBarcode}/basicdata'.format(patronBarcode=patronBarcode)
		return self._undifferentiatied(protocol,HTTPMethod,protection,suffixURI,patronPassword=patronPassword,**kwargs)

	def patronCirculateBlocksGet(self,patronBarcode,patronPassword,**kwargs):
		'''
			Validate that a patron is part of the Polaris database, and return
			blocks and status telling the caller if the given patron is
			allowed to perform a circulation activity (checkout).

			Example:
			>>> papi.patronCirculateBlocksGet(patronBarcode='patronbarcode',patronPassword='patronpassword')
		'''
		protocol = 'http'
		HTTPMethod = 'GET'
		protection = 'public'
		suffixURI = 'patron/{patronBarcode}/circulationblocks'.format(patronBarcode=patronBarcode)
		return self._undifferentiatied(protocol,HTTPMethod,protection,suffixURI,patronPassword=patronPassword,**kwargs)

	def createPatronBlocks(self,accessToken,accessSecret,patronBarcode,blockTypeID,blockValue,**kwargs):
		'''
			This protected method will create a block on a patron record.

			Example:
			>>> papi.createPatronBlocks(accessToken='accesstoken',accessSecret='accesssecret',patronBarcode='patronbarcode',blockTypeID='1',blockValue='hello world')
		'''
		protocol = 'https'
		HTTPMethod = 'POST'
		protection = 'protected'
		suffixURI = '{accessToken}/patron/{patronBarcode}/blocks'.format(accessToken=accessToken,patronBarcode=patronBarcode)
		data = {'BlockTypeID':blockTypeID,
				'BlockValue':blockValue}
		return self._undifferentiatied(protocol,HTTPMethod,protection,suffixURI,accessSecret=accessSecret,data=data,**kwargs)

	def patronHoldRequestsGet(self,patronBarcode,patronPassword,status,**kwargs):
		'''
			Returns a list of hold requests placed by the specified patron.
			The list can be filtered by ALL hold requests or by the status of
			the request.

			Example:
			>>> papi.patronHoldRequestsGet(patronBarcode='patronbarcode',patronPassword='patronpassword','all')
		'''
		protocol = 'http'
		HTTPMethod = 'GET'
		protection = 'public'
		suffixURI = 'patron/{patronBarcode}/holdrequests/{status}'.format(patronBarcode=patronBarcode,status=status)
		return self._undifferentiatied(protocol,HTTPMethod,protection,suffixURI,patronPassword=patronPassword,**kwargs)

	def patronItemsOutGet(self,patronBarcode,patronPassword,status,**kwargs):
		'''
			Returns list of items out to the specified patron. The list can be
			filtered by ALL items out, OVERDUE items only, or LOST items only.

			Example:
			>>> papi.patronItemsOutGet(patronBarcode='patronbarcode',patronPassword='patronpassword','all')
		'''
		protocol = 'http'
		HTTPMethod = 'GET'
		protection = 'public'
		suffixURI = 'patron/{patronBarcode}/itemsout/{status}'.format(patronBarcode=patronBarcode,status=status)
		return self._undifferentiatied(protocol,HTTPMethod,protection,suffixURI,patronPassword=patronPassword,**kwargs)

	def patronMessagesGet(self,patronBarcode,patronPassword,**kwargs):
		'''
			Retrieves a list of new and read patron messages.

			Example:
			>>> papi.patronMessagesGet(patronBarcode='patronbarcode',patronPassword='patronpassword')
		'''
		protocol = 'http'
		HTTPMethod = 'GET'
		protection = 'public'
		suffixURI = 'patron/{patronBarcode}/messages'.format(patronBarcode=patronBarcode)
		return self._undifferentiatied(protocol,HTTPMethod,protection,suffixURI,patronPassword=patronPassword,**kwargs)

	def patronMessageUpdateStatus(self,patronBarcode,patronPassword,messageType,messageID,**kwargs):
		'''
			Marks a message as read.

			Example:
			>>> papi.patronMessageUpdateStatus(patronBarcode='patronbarcode',patronPassword='patronpassword',messageType='freetext',messageID='2330')
		'''
		protocol = 'http'
		HTTPMethod = 'PUT'
		protection = 'public'
		suffixURI = 'patron/{patronBarcode}/messages/{messageType}/{messageID}'.format(patronBarcode=patronBarcode,messageType=messageType,messageID=messageID)
		return self._undifferentiatied(protocol,HTTPMethod,protection,suffixURI,patronPassword=patronPassword,**kwargs)

	def patronMessageDelete(self,patronBarcode,patronPassword,messageType,messageID,**kwargs):
		'''
			Delete a specific patron message.

			Example:
			>>> papi.patronMessageDelete(patronBarcode='patronbarcode',patronPassword='patronpassword',messageType='freetext',messageID='2330')
		'''
		protocol = 'http'
		HTTPMethod = 'DELETE'
		protection = 'public'
		suffixURI = 'patron/{patronBarcode}/messages/{messageType}/{messageID}'.format(patronBarcode=patronBarcode,messageType=messageType,messageID=messageID)
		return self._undifferentiatied(protocol,HTTPMethod,protection,suffixURI,patronPassword=patronPassword,**kwargs)

	def patronPreferencesGet(self,patronBarcode,patronPassword,**kwargs):
		'''
			Return preferences for a patron including reading list, email
			format, and notification type.

			Example:
			>>> papi.patronPreferencesGet(patronBarcode='patronbarcode',patronPassword='patronpassword')
		'''
		protocol = 'http'
		HTTPMethod = 'GET'
		protection = 'public'
		suffixURI = 'patron/{patronBarcode}/preferences'.format(patronBarcode=patronBarcode)
		return self._undifferentiatied(protocol,HTTPMethod,protection,suffixURI,patronPassword=patronPassword,**kwargs)

	def patronReadingHistoryClear(self,patronBarcode,patronPassword,**kwargs):
		'''
			Clears the historical list of items a patron has checked out.

			Example:
			>>> papi.patronReadingHistoryClear(patronBarcode='patronbarcode',patronPassword='patronpassword')
		'''
		protocol = 'http'
		HTTPMethod = 'DELETE'
		protection = 'public'
		suffixURI = 'patron/{patronBarcode}/readinghistory'.format(patronBarcode=patronBarcode)
		return self._undifferentiatied(protocol,HTTPMethod,protection,suffixURI,patronPassword=patronPassword,**kwargs)

	def patronRegistrationCreate(self,logonBranchID,logonUserID,logonWorkstationID,patronBranchID,nameFirst,nameLast,**kwargs):
		'''
			Create a new patron registration record; basic patron duplicate 
			detection (name, username, barcode) is performed.

			Example:
			>>> papi.patronRegistrationCreate(logonBranchID='3',logonUserID='2',logonWorkstationID='1',patronBranchID='3',nameFirst='Foo',nameLast='Bar')
		'''
		protocol = 'http'
		HTTPMethod = 'POST'
		protection = 'public'
		suffixURI = 'patron'
		data = {'LogonBranchID':logonBranchID,
				'LogonUserID':logonUserID,
				'LogonWorkstationID':logonWorkstationID,
				'PatronBranchID':patronBranchID,
				'PostalCode':kwargs.get('postalCode',None),
				'ZipPlusFour':kwargs.get('zipPlusFour',None),
				'City':kwargs.get('city',None),
				'State':kwargs.get('state',None),
				'County':kwargs.get('county',None),
				'CountryID':kwargs.get('countryID',None),
				'StreetOne':kwargs.get('streetOne',None),
				'StreetTwo':kwargs.get('streetTwo',None),
				'NameFirst':nameFirst,
				'NameLast':nameLast,
				'NameMiddle':kwargs.get('nameMiddle',None),
				'User1':kwargs.get('user1',None),
				'User2':kwargs.get('user2',None),
				'User3':kwargs.get('user3',None),
				'User4':kwargs.get('user4',None),
				'User5':kwargs.get('user5',None),
				'Gender':kwargs.get('gender',None),
				'Birthdate':kwargs.get('birthdate',None),
				'PhoneVoice1':kwargs.get('phoneVoice1',None),
				'PhoneVoice2':kwargs.get('phoneVoice2',None),
				'EmailAddress':kwargs.get('emailAddress',None),
				'LanguageID':kwargs.get('languageID',None),
				'DeliveryOptionID':kwargs.get('deliveryOptionID',None),
				'UserName':kwargs.get('username',None),
				'Password':kwargs.get('password',None),
				'Password2':kwargs.get('password2',None),
				'AltEmailAddress':kwargs.get('altEmailAddress',None),
				'PhoneVoice3':kwargs.get('phoneVoice3',None),
				'Phone1CarrierID':kwargs.get('phone1CarrierID',None),
				'Phone2CarrierID':kwargs.get('phone2CarrierID',None),
				'Phone3CarrierID':kwargs.get('phone3CarrierID',None),
				'Enable':kwargs.get('enable',None),
				'TxtPhoneNumber':kwargs.get('txtPhoneNumber',None),
				'Barcode':kwargs.get('barcode',None),
				'EReceiptOPtionID':kwargs.get('EReceiptOPtionID',None)}
		return self._undifferentiatied(protocol,HTTPMethod,protection,suffixURI,data=data,**kwargs)

	def patronRenewBlocksGet(self,accessToken,accessSecret,patronID,**kwargs):
		'''
			This method takes in a Patron ID and returns patron renewal blocks
			(if any). It also indicates whether the patron is allowed to renew
			(the blocks may be informational or actual blocks). It is a 
			protected method and staff must authenticate before calling this
			method.

			Example:
			>>> papi.patronRenewBlocksGet(accessToken='accesstoken',accessSecret='accesssecret,'121175')
		'''
		protocol = 'https'
		HTTPMethod = 'GET'
		protection = 'protected'
		suffixURI = '{accessToken}/circulation/patron/{patronID}/renewblocks'.format(accessToken=accessToken,patronID=patronID)
		return self._undifferentiatied(protocol,HTTPMethod,protection,suffixURI,accessSecret=accessSecret,**kwargs)

	def patronSavedSearchesGet(self,patronBarcode,patronPassword,**kwargs):
		'''
			Returns list of saved searches to the specified patron.

			Example:
			>>> papi.patronSavedSearchesGet(patronBarcode='patronbarcode',patronPassword='patronpassword')

		'''
		protocol = 'http'
		HTTPMethod = 'GET'
		protection = 'public'
		suffixURI = 'patron/{patronBarcode}/savedsearches'.format(patronBarcode=patronBarcode)
		return self._undifferentiatied(protocol,HTTPMethod,protection,suffixURI,patronPassword=patronPassword,**kwargs)

	def patronReadingHistoryGet(self,patronBarcode,patronPassword,page,rowsPerPage,**kwargs):
		'''
			Returns historical list of items patron has checked out. The
			procedure is capable of returning just a count of the total number
			of titles in the patron's check-out history, a list of all titles
			in the history, or a specific page of titles of a specified
			length.

			Example:
			>>> papi.patronReadingHistoryGet(patronBarcode='patronbarcode',patronPassword='patronpassword','10','10')
		'''
		protocol = 'http'
		HTTPMethod = 'GET'
		protection = 'public'
		suffixURI = 'patron/{patronBarcode}/readinghistory'.format(patronBarcode=patronBarcode)
		params = {'page':page,
				'rowsperpage':rowsPerPage}
		return self._undifferentiatied(protocol,HTTPMethod,protection,suffixURI,patronPassword=patronPassword,params=params,**kwargs)

	def patronSearch(self,accessToken,accessSecret,params,**kwargs):
		'''
			This protected method will return a list of patrons that match the
			search criteria specified in the CCL submitted by the user. Data
			returned includes the patron's name, barcode, Polaris Patron ID,
			and Polaris Organization ID. This method offers query parameters
			that allow the user to specify the number of patrons, the sort
			order, and page of data to retrieve.

			Example:
			>>> papi.patronSearch(accessToken='accesstoken',accessSecret='accesssecret',params={'q':'PATNL=Bar'})
		'''
		protocol = 'https'
		HTTPMethod = 'GET'
		protection = 'protected'
		suffixURI = '{accessToken}/search/patrons/Boolean'.format(accessToken=accessToken)
		return self._undifferentiatied(protocol,HTTPMethod,protection,suffixURI,accessSecret=accessSecret,params=params,**kwargs)

	def patronUpdate(self,patronBarcode,patronPassword,logonBranchID,logonUserID,logonWorkstationID,**kwargs):
		'''
			Update Patron Registration information. Currently supported fields
			are the following:

				- Reading List flag
				- Email Format
				- Delivery Option for Notices
				- Primary Phone Number
				- Phone Voice1
				- Email Address

			Example:
			>>> papi.patronUpdate(patronBarcode='patronbarcode',patronPassword='patronpassword',logonBranchID='3',logonUserID='2',logonWorkstationID='1',emailFormat='2')
		'''
		protocol = 'http'
		HTTPMethod = 'PUT'
		protection = 'public'
		suffixURI = 'patron/{patronBarcode}'.format(patronBarcode=patronBarcode)
		data = {'LogonBranchID':logonBranchID,
				'LogonUserID':logonUserID,
				'LogonWorkstationID':logonWorkstationID,
				'ReadingListFlag':kwargs.get('readingListFlag',None),
				'EmailFormat':kwargs.get('emailFormat',None),
				'DeliveryOption':kwargs.get('deliveryOption',None),
				'EmailAddress':kwargs.get('emailAddress',None),
				'PhoneVoice1':kwargs.get('phoneVoice1',None),
				'Password':kwargs.get('password',None)
				}
		return self._undifferentiatied(protocol,HTTPMethod,protection,suffixURI,patronPassword=patronPassword,data=data,**kwargs)

	def patronValidate(self,patronBarcode,patronPassword,**kwargs):
		'''
			Validate that a patron is part of the Polaris database.

			Example:
			>>> papi.patronValidate(patronBarcode='patronbarcode',patronPassword='patronpassword')
		'''
		protocol = 'http'
		HTTPMethod = 'GET'
		protection = 'public'
		suffixURI = 'patron/{patronBarcode}'.format(patronBarcode=patronBarcode)
		return self._undifferentiatied(protocol,HTTPMethod,protection,suffixURI,patronPassword=patronPassword,**kwargs)

	def sortOptionsGet(self,**kwargs):
		'''
			Returns list of valid sort options.

			Example:
			>>> papi.sortOptionsGet()
		'''
		protocol = 'http'
		HTTPMethod = 'GET'
		protection = 'public'
		suffixURI = 'sortoptions'
		return self._undifferentiatied(protocol,HTTPMethod,protection,suffixURI,**kwargs)

	def synchItemsByBibIDGet(self,accessToken,accessSecret,bibID,**kwargs):
		'''
			Example:
			>>> papi.synchTasksCheckout(self,accessToken='accesstoken',accessSecret='accesssecret',workstationID='1',userID='2',vendorID='james',vendorContractID='12345',uniqueRecordID,patronBarcode,itemExpireDateTime,transactionDateTime)
		'''

		protocol = 'https'
		HTTPMethod = 'GET'
		protection = 'protected'
		suffixURI = '{accessToken}/synch/items/bibid/{bibID}'.format(accessToken=accessToken,bibID=bibID)
		return self._undifferentiatied(protocol,HTTPMethod,protection,suffixURI,accessSecret=accessSecret,**kwargs)


	def synchTasksCheckout(self,accessToken,accessSecret,workstationID,userID,vendorID,vendorContractID,uniqueRecordID,patronBarcode,itemExpireDateTime,transactionDateTime,**kwargs):
		'''
			Example:
			>>> papi.synchTasksCheckout(self,accessToken='accesstoken',accessSecret='accesssecret',workstationID='1',userID='2',vendorID='james',vendorContractID='12345',uniqueRecordID,patronBarcode,itemExpireDateTime,transactionDateTime)
		'''

		protocol = 'https'
		HTTPMethod = 'PUT'
		protection = 'protected'
		params={'wsid':workstationID,
				'userid':userID}
		data = {'VendorID':vendorID,
				'VendorContractID':vendorContractID,
				'UniqueRecordID':uniqueRecordID,
				'PatronBarcode':patronBarcode,
				'ItemExpireDateTime':'/Date({timestamp}000-0000)/'.format(timestamp=itemExpireDateTime),
				'TransactionDateTime':'/Date({timestamp}000-0000)/'.format(timestamp=transactionDateTime)
				} 
		suffixURI = '{accessToken}/synch/tasks/checkout'.format(accessToken=accessToken)
		return self._undifferentiatied(protocol,HTTPMethod,protection,suffixURI,accessSecret=accessSecret,params=params,data=data,**kwargs)


