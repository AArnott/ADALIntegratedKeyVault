namespace Get_AzureKeyVaultSecret
{
    using System;
    using System.Net.Http;
    using System.Threading.Tasks;
    using Microsoft.Azure.KeyVault; // Install-Package Microsoft.Azure.KeyVault
    using Microsoft.IdentityModel.Clients.ActiveDirectory; // Install-Package Microsoft.IdentityModel.Clients.ActiveDirectory

    public class GetAzureKeyVaultSecret
    {
        /// <summary>
        /// The Application ID for the app registered with the Azure Active Directory.
        /// </summary>
        /// <remarks>
        /// Register your application in https://portal.azure.com/ within the "App Registrations" blade.
        /// Be sure to grant your app permissions to "Azure Key Vault (AzureKeyVault)".
        /// </remarks>
        public Guid ADALClientId { get; set; }

        /// <summary>
        /// A URI recorded for the AAD registered app as a valid redirect URI.
        /// </summary>
        /// <remarks>
        /// For example: "https://myapp/finish". Literally, it could be that. You don't need to have a server responding to this URI.
        /// </remarks>
        public Uri ADALRedirectUri { get; set; }

        /// <remarks>
        /// For example: https://yourCoolApp.vault.azure.net/
        /// </remarks>
        public Uri KeyVaultAddress { get; set; }

        /// <summary>
        /// Gets or sets the secret whose value should be retrieved.
        /// </summary>
        public string SecretName { get; set; }

        /// <summary>
        /// Gets or sets a value indicating whether the cmdlet should fail rather than prompt the user for credentials.
        /// </summary>
        public bool NonInteractive { get; set; }

        /// <inheritdoc />
        public async Task<string> GetSecretAsync()
        {
            var keyVault = new KeyVaultClient(
                          new KeyVaultClient.AuthenticationCallback(this.GetAccessTokenAsync),
                          new HttpClient());

            var secret = await keyVault.GetSecretAsync(this.KeyVaultAddress.AbsoluteUri, this.SecretName);
            return secret.Value;
        }

        private async Task<string> GetAccessTokenAsync(string authority, string resource, string scope)
        {
            var context = new AuthenticationContext(authority, TokenCache.DefaultShared);
            AuthenticationResult result;
            try
            {
                // Try to get the token from Windows auth
                result = await context.AcquireTokenAsync(resource, this.ADALClientId.ToString(), new UserCredential());
            }
            catch (AdalException)
            {
#if NET462
                try
                {
                    // Try to get the token silently, either using the token cache or browser cookies.
                    result = await context.AcquireTokenAsync(resource, this.ADALClientId.ToString(), this.ADALRedirectUri, new PlatformParameters(PromptBehavior.Never));
                }
                catch (AdalException) when (!this.NonInteractive)
                {
                    // OK, ultimately fail: ask the user to authenticate manually.
                    result = await context.AcquireTokenAsync(resource, this.ADALClientId.ToString(), this.ADALRedirectUri, new PlatformParameters(PromptBehavior.Always));
                }
#else
                // Try to get the token silently, either using the token cache or browser cookies.
                result = await context.AcquireTokenAsync(resource, this.ADALClientId.ToString(), this.ADALRedirectUri, new PlatformParameters());
#endif
            }

            return result.AccessToken;
        }
    }
}
