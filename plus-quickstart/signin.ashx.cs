/*
 * Copyright 2013 Google Inc. All Rights Reserved.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
namespace Google.Plus.Samples.Quickstart
{
    using System;
    using System.Collections.Generic;
    using System.IO;
    using System.Linq;
    using System.Net;
    using System.Text;
    using System.Text.RegularExpressions;
    using System.Web;
    using System.Web.Compilation;
    using System.Web.Routing;
    using System.Web.SessionState;

    using Google.Apis.Authentication.OAuth2;
    using Google.Apis.Authentication.OAuth2.DotNetOpenAuth;
    using Google.Apis.Plus.v1;
    using Google.Apis.Plus.v1.Data;
    using Google.Apis.Services;
    using Google.Apis.Util;

    using DotNetOpenAuth.Messaging;
    using DotNetOpenAuth.OAuth2;

    using Newtonsoft.Json;

    /// <summary>
    /// This is a minimal implementation of Google+ Sign-In that
    /// demonstrates:
    /// <list type="bullet">
    /// <item>
    ///   Using the Google+ Sign-In button to get an OAuth 2.0 refresh token.
    /// </item>
    /// <item>
    ///   Exchanging the refresh token for an access token.
    /// </item>
    /// <item>
    ///   Making Google+ API requests with the access token, including
    ///   getting a list of people that the user has circled.
    /// </item>
    /// <item>
    ///   Disconnecting the app from the user's Google account and revoking
    ///   tokens.
    /// </item>
    /// </list>
    /// </summary>
    /// @author class@google.com (Gus Class)
    public class Signin : IHttpHandler, IRequiresSessionState, IRouteHandler
    {
        // These come from the APIs console:
        //   https://code.google.com/apis/console

        /// <summary> This is the application's client ID.</summary>
        public static string CLIENT_ID = "1034213464607.apps.googleusercontent.com";

        /// <summary>The client secret. Keep this secure.</summary>
        public static string CLIENT_SECRET = "UScZsbek5LgEgtcaDcan8EUc  ";

        // Configuration that you probably don't need to change.

        /// <summary>
        /// The application name rendered to the user in the HTML template.
        /// </summary>
        public static string APP_NAME = "Google+ C# Quickstart";

        /// <summary>
        /// An internal variable used by the OAuth client library.
        /// </summary>
        private IAuthorizationState authState;

        /// <summary>Used to perform API calls against Google+.</summary>
        private PlusService service = null;

        /// <summary>
        /// Gets a value indicating whether to disable multiple requests on the
        /// same instance.
        /// </summary>
        public bool IsReusable
        {
            get { return false; }
        }

        /// <summary>
        /// The CreateState function will generate a state that can be
        /// used to initialize the API client.
        /// </summary>
        /// <param name="accessToken">An access token string from an
        /// OAuth2 flow.</param>
        /// <param name="refreshToken">A refresh token string from an
        /// OAuth2 flow.</param>
        /// <param name="issued">A DateTime object representing the time
        /// that the token was issued.</param>
        /// <param name="expires">A DateTime object indicating when the
        /// token expires.</param>
        /// <returns>An authorization state for the API client.</returns>
        public static IAuthorizationState CreateState(
            string accessToken,
            string refreshToken,
            DateTime issued,
            DateTime expires)
        {
            IAuthorizationState state = new AuthorizationState()
            {
                AccessToken = accessToken,
                RefreshToken = refreshToken,
                AccessTokenIssueDateUtc = issued,
                AccessTokenExpirationUtc = expires
            };
            return state;
        }

        /// <summary>Processes the request based on the path.</summary>
        /// <param name="context">Contains the request and response.</param>
        public void ProcessRequest(HttpContext context)
        {
            // Redirect base path to signin.
            if (context.Request.Path.EndsWith("/"))
            {
                context.Response.RedirectPermanent("signin.ashx");
            }

            // This is reached when the root document is passed. Return HTML
            // using index.html as a template.
            if (context.Request.Path.EndsWith("/signin.ashx"))
            {
                string state = (string)context.Session["state"];

                // Store a random string in the session for verifying
                // the responses in our OAuth2 flow.
                if (state == null)
                {
                    Random random = new Random((int)DateTime.Now.Ticks);
                    StringBuilder builder = new StringBuilder();
                    for (int i = 0; i < 13; i++)
                    {
                        builder.Append(Convert.ToChar(
                                Convert.ToInt32(Math.Floor(
                                        (26 * random.NextDouble()) + 65))));
                    }

                    state = builder.ToString();
                    context.Session["state"] = state;
                }

                // Render the templated HTML.
                string templatedHTML = File.ReadAllText(
                     context.Server.MapPath("index.html"));
                templatedHTML = Regex.Replace(
                    templatedHTML,
                    "[{]{2}\\s*APPLICATION_NAME\\s*[}]{2}",
                    APP_NAME);
                templatedHTML = Regex.Replace(
                    templatedHTML,
                    "[{]{2}\\s*CLIENT_ID\\s*[}]{2}",
                    CLIENT_ID);
                templatedHTML = Regex.Replace(
                    templatedHTML,
                    "[{]{2}\\s*STATE\\s*[}]{2}",
                    state);

                context.Response.ContentType = "text/html";
                context.Response.Write(templatedHTML);
                return;
            }

            if (context.Session["authState"] == null)
            {
                // The connect action exchanges a code from the sign-in button,
                // verifies it, and creates OAuth2 credentials.
                if (context.Request.Path.Contains("/connect"))
                {
                    // Get the code from the request POST body.
                    using (var sr =
                        new StreamReader(context.Request.InputStream))
                    {
                        string code = sr.ReadToEnd();

                        string state = context.Request["state"];

                        // Test that the request state matches the session's.
                        if (!state.Equals(context.Session["state"]))
                        {
                            context.Response.StatusCode = 401;
                            return;
                        }

                        // Manually perform the OAuth2 flow for now.
                        var authObject = ManualCodeExchanger.ExchangeCode(code);

                        // Create an authorization state from the token.
                        context.Session["authState"] = CreateState(
                            authObject.AccessToken,
                            authObject.RefreshToken,
                            DateTime.UtcNow,
                            DateTime.UtcNow.AddSeconds(authObject.ExpiresIn));

                        string id_token = authObject.IdToken;
                        string[] segments = id_token.Split('.');

                        // The ID token consists of Base64-encoded JSON. To
                        // ensure that the Base64 segment can be parsed, the
                        // string must be padded to 4-character segments.
                        string base64EncoodedJsonBody = segments[1];
                        int mod4 = base64EncoodedJsonBody.Length % 4;
                        if (mod4 > 0)
                        {
                            base64EncoodedJsonBody += new string('=', 4 - mod4);
                        }

                        byte[] encodedBodyAsBytes =
                            System.Convert.FromBase64String(
                                base64EncoodedJsonBody);
                        string json_body =
                            System.Text.Encoding.UTF8.GetString(
                                encodedBodyAsBytes);
                        IDTokenJsonBodyObject bodyObject =
                            JsonConvert.DeserializeObject<IDTokenJsonBodyObject>
                                (json_body);
                        string gplus_id = bodyObject.Subject;
                    }
                }
                else
                {
                    // No cached state and we are not connecting.
                    context.Response.StatusCode = 400;
                    return;
                }
            }
            else if (context.Request.Path.Contains("/connect"))
            {
                // The user is already connected and credentials are cached.
                context.Response.ContentType = "application/json";
                context.Response.StatusCode = 200;
                context.Response.Write(
                    JsonConvert.SerializeObject(
                        "Current user is already connected."));
                return;
            }
            else
            {
                // Register the authenticator and construct the Plus service
                // for performing API calls on behalf of the user.
                authState = (IAuthorizationState)context.Session["authState"];
                AuthorizationServerDescription description =
                    GoogleAuthenticationServer.Description;
                var provider = new WebServerClient(description);
                provider.ClientIdentifier = CLIENT_ID;
                provider.ClientSecret = CLIENT_SECRET;
                var authenticator =
                    new OAuth2Authenticator<WebServerClient>(
                        provider,
                        GetAuthorization)
                    {
                        NoCaching = true
                    };
                service = new PlusService(
                    new BaseClientService.Initializer()
                    {
                      Authenticator = authenticator
                    });
            }

            // Perform an authenticated API request to retrieve the list of
            // people that the user has made visible to the app.
            if (context.Request.Path.Contains("/people"))
            {
                // Get the PeopleFeed for the currently authenticated user.
                PeopleFeed pf =
                    service.People.List("me",
                        PeopleResource.ListRequest.CollectionEnum.Visible).Execute();

                // This JSON, representing the people feed, will later be
                // parsed by the JavaScript client.
                string jsonContent =
                    Newtonsoft.Json.JsonConvert.SerializeObject(pf);
                context.Response.ContentType = "application/json";
                context.Response.Write(jsonContent);
                return;
            }

            // Disconnect the user from the application by revoking the tokens
            // and removing all locally stored data associated with the user.
            if (context.Request.Path.Contains("/disconnect"))
            {
                // Perform a get request to the token endpoint to revoke the
                // refresh token.
                authState = (IAuthorizationState)context.Session["authState"];
                string token = (authState.RefreshToken != null) ?
                    authState.RefreshToken : authState.AccessToken;

                WebRequest request = WebRequest.Create(
                    "https://accounts.google.com/o/oauth2/revoke?token=" +
                    token);

                WebResponse response = request.GetResponse();

                // Remove the cached credentials.
                context.Session["authState"] = null;

                // You could reset the state in the session but you must also
                // reset the state on the client.
                // context.Session["state"] = null;
                context.Response.Write(
                    response.GetResponseStream().ToString().ToCharArray());
                return;
            }
        }

        /// <summary>
        /// Implements IRouteHandler interface for mapping routes to this
        /// IHttpHandler.
        /// </summary>
        /// <param name="requestContext">Information about the request.
        /// </param>
        /// <returns>The current page handler.</returns>
        public IHttpHandler GetHttpHandler(RequestContext requestContext)
        {
            var page = BuildManager.CreateInstanceFromVirtualPath(
                "~/signin.ashx", typeof(IHttpHandler)) as IHttpHandler;
            return page;
        }

        /// <summary>
        /// Gets the authorization object for the client-side flow.
        /// </summary>
        /// <param name="client">The client used for authorization.
        /// </param>
        /// <returns>An authorization state that can be used for API queries.
        /// </returns>
        private IAuthorizationState GetAuthorization(WebServerClient client)
        {
            // If we don't yet have user, use the client to perform
            // authorization.
            if (authState != null)
            {
                HttpRequestInfo reqinfo =
                    new HttpRequestInfo(HttpContext.Current.Request);
                client.ProcessUserAuthorization(reqinfo);
            }
            else
            {
                authState = (IAuthorizationState)HttpContext.Current
                        .Session["AUTH_STATE"];
            }

            // Check if we need to refresh the authorization state and refresh
            // it if necessary.
            if (authState != null)
            {
                if (authState.AccessToken == null ||
                    DateTime.UtcNow > authState.AccessTokenExpirationUtc)
                {
                    client.RefreshToken(authState);
                }

                return authState;
            }

            // If we fall through to here, perform an authorization request.
            OutgoingWebResponse response =
                client.PrepareRequestUserAuthorization(this.authState.Scope);

            response.Send();

            // Note: response.send will throw a ThreadAbortException to prevent
            // sending another response.
            return null;
        }
    }

    /// <summary>Encapsulates JSON data for ID token body.</summary>
    public class IDTokenJsonBodyObject
    {
        /// <summary>The issuer for the ID token.</summary>
        [Newtonsoft.Json.JsonPropertyAttribute("iss")]
        public string Issue { get; set; }

        /// <summary> The audience for the ID token.</summary>
        [Newtonsoft.Json.JsonPropertyAttribute("aud")]
        public string Audience { get; set; }

        /// <summary>A hash used for verification of the access token.</summary>
        [Newtonsoft.Json.JsonPropertyAttribute("at_hash")]
        public string AccessTokenHash { get; set; }

        /// <summary>The authorized party that sent the tokens.</summary>
        [Newtonsoft.Json.JsonPropertyAttribute("azp")]
        public string AuthParty { get; set; }

        /// <summary>Used to verify the authorization code.</summary>
        [Newtonsoft.Json.JsonPropertyAttribute("c_hash")]
        public string CodeHash { get; set; }

        /// <summary>The subject the ID token was issued to.</summary>
        [Newtonsoft.Json.JsonPropertyAttribute("sub")]
        public string Subject { get; set; }

        /// <summary>The time that the ID token was issued.</summary>
        [Newtonsoft.Json.JsonPropertyAttribute("iat")]
        public int IssuedAt { get; set; }

        /// <summary>The expiration time.</summary>
        [Newtonsoft.Json.JsonPropertyAttribute("exp")]
        public int ExpirationTime { get; set; }
    }
}
