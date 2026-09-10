export type MailStatus = "accepted"|"queued"|"leased"|"sending"|"retrying"|"sent"|"delivered"|"bounced"|"complained"|"failed";
export interface MailIdentity { identity:string; address:string; domain:string; status:"pending"|"active" }
export interface MailTemplate { subject?:string; text?:string; html?:string }
export interface MailEvent { event_id:string; message_id:string; timestamp:string; event_type:string; attempt:number; worker_id?:string|null }
export interface MailMessage { message_id:string; application_id:string; tenant_id?:string|null; identity:string; from:string; to:string[]; cc:string[]; bcc:string[]; reply_to:string[]; subject:string; text:string; html:string; template?:string|null; variables:Record<string,unknown>; metadata:Record<string,unknown>; status:MailStatus; created_at:string; updated_at:string; links:string[]; events?:MailEvent[] }
export interface DeliveryResult { status:"sent"|"retry"|"failed"; error?:unknown; message_id?:string; metadata?:Record<string,unknown> }
export interface MailTransport { send(message:MailMessage):Promise<DeliveryResult> }
export interface MailCapability { readonly name:"mail"; readonly version:"1"; parse(source:string):MailContract; snapshot(contract:MailContract):MailContractSnapshot }
export interface MailContract { capability:"mail"; identities:Record<string,string>; templates:Record<string,string> }
export interface MailContractSnapshot { capability:"mail"; version:"1"; identities:string[]; templates:string[] }
export class MailPortError extends Error { code:string; details?:unknown; constructor(code:string,message:string,details?:unknown) }
export const ERROR_CODES:Record<string,string>;
export const mailCapability:MailCapability;
export function defineMailCapability():MailCapability;
export function registerMailCapability<T extends {register(capability:MailCapability):unknown}>(registry:T):T;
export function defineTemplate<T extends MailTemplate>(template:T):Readonly<T>;
export function parseMailDsl(source:string):MailContract;
export function generateMailContractSnapshot(contract:MailContract):MailContractSnapshot;
