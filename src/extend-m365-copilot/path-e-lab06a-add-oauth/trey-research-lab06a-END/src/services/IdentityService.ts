import { HttpRequest } from "@azure/functions";
import { HttpError } from './Utilities';
import { Consultant } from '../model/baseModel';
import { ApiConsultant } from '../model/apiModel';
import { TokenValidator, ValidateTokenOptions, getEntraJwksUri } from 'jwt-validate';

// This is a DEMO ONLY identity solution.
import ConsultantApiService from "./ConsultantApiService";

class Identity {
    private validatorPromise: Promise<TokenValidator>;
    private requestNumber = 1;  // Number the requests for logging purposes

    public async validateRequest(req: HttpRequest): Promise<ApiConsultant> {

        // Default user used for unauthenticated testing
        let userId = "1";
        let userName = "Avery Howard";
        let userEmail = "avery@treyresearch.com";

        // Try to validate the token and get user's basic information
        try {
            const { AAD_APP_CLIENT_ID, AAD_APP_TENANT_ID } = process.env;
            const token = req.headers.get("Authorization")?.split(" ")[1];
            if (!token) {
                throw new HttpError(401, "Authorization token not found");
            }

            // Always use the same validator, stored in the validatorPromise value, to allow caching
            // and avoid extra calls to get the EntraID JWKS URI
            let validator = await (async (): Promise<TokenValidator> => {
                if (!this.validatorPromise) {
                    this.validatorPromise = new Promise(async (resolve) => {
                        const { AAD_APP_TENANT_ID } = process.env;
                        const entraJwksUri = await getEntraJwksUri(AAD_APP_TENANT_ID);
                        let validator = new TokenValidator({
                            jwksUri: entraJwksUri
                        });
                        console.log("Token validator created");
                        resolve(validator);
                    });
                }
                return this.validatorPromise;
            })();        

            const options: ValidateTokenOptions = {
                allowedTenants: [AAD_APP_TENANT_ID],
                audience: `${AAD_APP_CLIENT_ID}`,
                issuer: `https://login.microsoftonline.com/${AAD_APP_TENANT_ID}/v2.0`,
                scp: ["access_as_user"]
            };

            // validate the token
            const validToken = await validator.validateToken(token, options);

            userId = validToken.oid;
            userName = validToken.name;
            userEmail = validToken.preferred_username;
            console.log(`Request ${this.requestNumber++}: Token is valid for user ${userName} (${userId})`);
        }
        catch (ex) {
            // Token is missing or invalid - return a 401 error
            console.error(ex);
            throw new HttpError(401, "Unauthorized");
        }

        // Get the consultant record for this user; create one if necessary
        let consultant: ApiConsultant = null;
        try {
            consultant = await ConsultantApiService.getApiConsultantById(userId);
        }
        catch (ex) {
            if (ex.status !== 404) {
                throw ex;
            }
            // Consultant was not found, so we'll create one below
            consultant = null;
        }
        if (!consultant) consultant = await this.createConsultantForUser(userId, userName, userEmail);

        return consultant;
    }

    private async createConsultantForUser(userId: string, userName: string,
            userEmail: string): Promise<ApiConsultant> {

        // Create a new consultant record for this user with default values
        const consultant: Consultant = {
            id: userId,
            name: userName,
            email: userEmail,
            phone: "1-555-123-4567",
            consultantPhotoUrl: "https://microsoft.github.io/copilot-camp/demo-assets/images/consultants/Unknown.jpg",
            location: {
                street: "One Memorial Drive",
                city: "Cambridge",
                state: "MA",
                country: "USA",
                postalCode: "02142",
                latitude: 42.361366,
                longitude: -71.081257
            },
            skills: ["JavaScript", "TypeScript"],
            certifications: ["Azure Development"],
            roles: ["Architect", "Project Lead"]
        };
        const result = await ConsultantApiService.createApiConsultant(consultant);
        return result;
    }
}

export default new Identity();






