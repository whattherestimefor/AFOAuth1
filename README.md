AFOAuth1
========

AFNetworking 2.0-compatible classes for using the OAuth1 protocol

You may wish to subclass AFOAuth1SessionManager to handle authentication with your chosen service

You should not have to use AFOAuth1RequestSerializer directly.

After authentication, save the access token you receive and then use the authenticated GET and POST methods provided to communicate with the service.

NOTE:  The various methods in the NSCopying protocol are incomplete in this initial push.

Only GET and POST have been tested.
