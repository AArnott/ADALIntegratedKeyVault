using System;
using System.Management.Automation;
using System.Net.Http;
using System.Threading.Tasks;
using Microsoft.Azure.KeyVault; // Install-Package Microsoft.Azure.KeyVault
using Microsoft.IdentityModel.Clients.ActiveDirectory; // Install-Package Microsoft.IdentityModel.Clients.ActiveDirectory

namespace AzureKeyVaultCmdlets
{
    [Cmdlet(VerbsCommon.Get, "AzureKeyVaultSecret")]
    public class GetAzureKeyVaultSecret : Cmdlet
    {
        /// <summary>
        /// The Application ID for the app registered with the Azure Active Directory.
        /// </summary>
        /// <remarks>
        /// Register your application in https://portal.azure.com/ within the "App Registrations" blade.
        /// Be sure to grant your app permissions to "Azure Key Vault (AzureKeyVault)".
        /// </remarks>
        [Parameter(Mandatory = true)]
        public string ADALClientId { get; set; }

        /// <summary>
        /// A URI recorded for the AAD registered app as a valid redirect URI.
        /// </summary>
        /// <remarks>
        /// For example: "https://myapp/finish". Literally, it could be that. You don't need to have a server responding to this URI.
        /// </remarks>
        [Parameter(Mandatory = true)]
        public Uri ADALRedirectUri { get; set; }

        /// <remarks>
        /// For example: https://yourCoolApp.vault.azure.net/
        /// </remarks>
        [Parameter(Mandatory = true)]
        public Uri KeyVaultAddress { get; set; }

        /// <summary>
        /// Gets or sets the secret whose value should be retrieved.
        /// </summary>
        [ValidatePattern(@"[a-zA-Z0-9\-]+")]
        [Parameter(Mandatory = true)]
        public string SecretName { get; set; }

        /// <summary>
        /// Gets or sets a value indicating whether the cmdlet should fail rather than prompt the user for credentials.
        /// </summary>
        [Parameter]
        public SwitchParameter NonInteractive { get; set; }

        /// <inheritdoc />
        protected override void ProcessRecord()
        {
            var keyVault = new KeyVaultClient(
                          new KeyVaultClient.AuthenticationCallback(this.GetAccessTokenAsync),
                          new HttpClient());

            var secret = keyVault.GetSecretAsync(this.KeyVaultAddress.AbsoluteUri, this.SecretName).GetAwaiter().GetResult();
            this.WriteObject(secret.Value);
        }

        private async Task<string> GetAccessTokenAsync(string authority, string resource, string scope)
        {
            var context = new AuthenticationContext(authority, TokenCache.DefaultShared);
            AuthenticationResult result;
            try
            {
                // Try to get the token from Windows auth
                result = await context.AcquireTokenAsync(resource, this.ADALClientId, new UserCredential());
            }
            catch (AdalException)
            {
                try
                {
                    // Try to get the token silently, either using the token cache or browser cookies.
                    result = await context.AcquireTokenAsync(resource, this.ADALClientId, this.ADALRedirectUri, new PlatformParameters(PromptBehavior.Never));
                }
                catch (AdalException) when (!this.NonInteractive)
                {
                    // OK, ultimately fail: ask the user to authenticate manually.
                    result = await context.AcquireTokenAsync(resource, this.ADALClientId, this.ADALRedirectUri, new PlatformParameters(PromptBehavior.Always));
                }
            }

            return result.AccessToken;
        }
    }
}
