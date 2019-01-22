To set up the client secret:

$secret_path = "<Enter path here>"	# e.g. Module root or Program Files
Get-Credential -Credential (Get-Credential) | Export-Clixml $secret_path
	Username: cranleighae
	Password: <Client secret from iSAMS>