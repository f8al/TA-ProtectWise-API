# TA-ProtectWise-API
Better version of the ProtectWise TA that doesn't require the protectwise-emitter daemon

This app uses Pythons requests library alongside ConfigParser to pull protectwise data from the ProtectWise Restful API,
Thus eliminating the need to run their propretary daemon to bring data in from the Visualizer cloud.

You will need an encrypted credential to run this input. Only one api is 

`Realm`: `protectwise`

You will need to create a protectwise.conf in local with the following KV pair contents:

If you'd like to use a different index (i.e. NOT MAIN), please configure input appropriately, and update the eventtype.

```
[protectwise]
apiUrl = https://api.protectwise.com/api/v1
email = your_protectwise_visualizer_account@email.tld
password = your protectwise visualizer account password
```
