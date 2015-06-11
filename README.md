# Cloud Insight API

This an example project which shows how to access the [Cloud Insight API](https://console.cloudinsight.alertlogic.com/api/) using Python.

## Overview
The [Cloud Insight API](https://console.cloudinsight.alertlogic.com/api/) is a REST API which provide many services related with the Cloud Insight system.
The data transmition protocol is JSON objects, the API receives and send answers as JSON objects and send HTTP error or confirmation as HTTP status code.
The [CloudInsightAPI](./cloudinsight.py) class provide an interface and some example methods to access the [Cloud Insight API](https://console.cloudinsight.alertlogic.com/api/). All the objects accessed by [CloudInsightAPI](./cloudinsight.py) will have the JSON response converted to generic Python objects ([Bunch](https://github.com/dsc/bunch)) which can have their properties accessed by obj.property syntax instead dictionary syntax. The print of the objects will return a JSON formatted string to facilitade the visualization of the object data.
The requests are made using the [Requests](http://docs.python-requests.org/en/latest/) library and will raise [requests.exceptions.RequestException](http://docs.python-requests.org/en/latest/api/#requests.exceptions.RequestException) when some request fail accorting to the status code error.

The [program.py](program.py) provide an example of a command line script implementation of the CloudInsightAPI class

## Methods

### CloudInsightAPI()
The CloudInsightAPI instance will hold the API URL, the user information, the access token used on that session, a dictionary of the user credentials and a dictionary of enviroments.

```python
class CloudInsightAPI:
	def __init__(self):
		self._BASE_URL = "https://api.cloudinsight.alertlogic.com"
		self.credentials = dict()
		self.sources = dict()
		self.user = None
		self.token = ""
```

### login(username, password)
@param username (string)
The user name to log into the system
@param password (string)
The user password
@return boolean if the login succeed or not

### validate(credential) (static method)
@param credential (object)
The object which contains the credential information
@return boolean
if the given credential information is validate

### createCredential(type, name, dict_cred_data)
```java
/** @param type (string)
 The type of the credential
 @param name (string)
 The name of the credential
 @param dict_cred_data (dictionary)
 The dictionary which contains the key and values accorting to the credential configuration needed
 @return (object)
 The credential created */
```
### listCredentials(filters="")
@param filters (string)
The filters to apply in the API credential search according to the [CloudInsightAPI filters objects](https://console.cloudinsight.alertlogic.com/api/sources/#api-_footer)
@return (dictionary)
This method save locally in the instance a dictionary of the search results where the UUID of each item is the key and the credential object itself is the value. It also returns that dictionary

### getCredential(credential_id)
@param credential_id (string)
The UUID of the credential
@return (object)
The credential object found or raise an 404 exceptions if any object was found.

### deleteCredential(credential_id)
@param credential_id (string)
The UUID of the credential
@return (void)
This remove the credential from system and from the instance dictionary as well

### createSource(self, name, collection_type, credential, scope, discover, scan):
@param name (string)
The name of the source
@param collection_type (string)
The collection type of the source
@param credential (object)
The credential object which will be added to the source
@param scope (dictionary)
The scope with the path of the sources to be included or excluded from the enviroment
@param discover (boolean)
Whether or not the system system should discover the enviroment
@param scan (boolean)
Whether or not the system should scan the sources
@return (object)
The source created

### listSources(filters="")
@param filters (string)
The filters to apply in the API credential search according to the [CloudInsightAPI filters objects](https://console.cloudinsight.alertlogic.com/api/sources/#api-_footer)
@return (dictionary)
This method save locally in the instance a dictionary of the search results where the UUID of each item is the key and the source object itself is the value. It also returns that dictionary

### getSource(source_id)
@param source_id (string)
The UUID of the source
@return (object)
The source object found or raise an 404 exceptions if any object was found.

### deleteSource(source_id)
@param source_id (string)
The UUID of the source
@return (void)
This remove the source from system and from the instance dictionary as well