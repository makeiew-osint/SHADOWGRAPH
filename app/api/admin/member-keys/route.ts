import { issueMemberKeys, json } from '../../../../lib/key-auth';
export const dynamic='force-dynamic';
export async function POST(request:Request){try{return await issueMemberKeys(request)}catch{return json({error:'Не удалось выпустить ключи.'},503)}}
