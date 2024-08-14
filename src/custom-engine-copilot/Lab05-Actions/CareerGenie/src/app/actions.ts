import { ApplicationTurnState } from "./state";
import {getUserDisplayName} from './app';

function getCandidates(state: ApplicationTurnState, list: string): string[] {
    ensureListExists(state, list);
    return state.conversation.lists[list];
}
  
function setCandidates(state: ApplicationTurnState, list: string, Candidates: string[]): void {
ensureListExists(state, list);
state.conversation.lists[list] = Candidates ?? [];
}

function ensureListExists(state: ApplicationTurnState, listName: string): void {
if (typeof state.conversation.lists != 'object') {
    state.conversation.lists = {};
}

if (!Object.prototype.hasOwnProperty.call(state.conversation.lists, listName)) {
    state.conversation.lists[listName] = [];
}
}
  
function deleteList(state: ApplicationTurnState, listName: string): void {
if (
    typeof state.conversation.lists == 'object' &&
    Object.prototype.hasOwnProperty.call(state.conversation.lists, listName)
) {
    delete state.conversation.lists[listName];
}
}
  
async function sendLists(state: ApplicationTurnState, token): Promise<string> {

    const email = await createEmailContent(state.conversation.lists, token);

    const sendEmail = await fetch(`https://graph.microsoft.com/v1.0/me/sendMail`,
        {
        "method": "POST",
        "headers": {
            "Accept": "application/json",
            "Content-Type": "application/json",
            "Authorization": `Bearer ${token}`
        },
        "body": JSON.stringify(email)
        });

        if(sendEmail.ok){
            return email.message.body.content;
        }
        else {
            console.log(`Error ${sendEmail.status} calling Graph in sendToHR: ${sendEmail.statusText}`);
            return 'Error sending email';
        }
}
   
async function createEmailContent(lists, token) {
let emailContent = '';
for (const listName in lists) {
    if (lists.hasOwnProperty(listName)) {
    emailContent += `${listName}:\n`;
    lists[listName].forEach(candidate => {
        emailContent += `  • ${candidate}\n`;
    });
    emailContent += '\n'; // Add an extra line between different lists
    }
}

const profileName = await getUserDisplayName(token);

const email ={
    "message": {
    "subject": "Request to Schedule Interviews with Shortlisted Candidates",
    "body": {
        "contentType": "Text",
        "content": `Hello HR Team, \nI hope this email finds you well. \n\nCould you please assist in scheduling 1:1 interviews with the following shortlisted candidates? \n\n${emailContent} Please arrange suitable times and send out the calendar invites accordingly. \n\n Best Regards, \n ${profileName}`
    },
    "toRecipients": [
        {
        "emailAddress": {
            "address": "<YOUR-EMAIL-ADDRESS>"
        }
        }
    ]
    },
    "saveToSentCandidates": "true"
};
return await email;
}

export { getCandidates, setCandidates, ensureListExists, deleteList, sendLists };