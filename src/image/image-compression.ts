import { detectImageMime,validateImageDimensions,ProtectedImageError } from '../crypto/protected-image';
export type CompressionMode='original'|'standard'|'hd';
export async function compressOriginal(bytes:Uint8Array,filename:string,targetBytes:number,signal?:AbortSignal){
 if(bytes.length<=targetBytes)return {bytes,filename};
 const mime=detectImageMime(bytes),dimensions=validateImageDimensions(bytes);signal?.throwIfAborted();
 const bitmap=await createImageBitmap(new Blob([Uint8Array.from(bytes)],{type:mime})),canvas=document.createElement('canvas');
 try{
  const ctx=canvas.getContext('2d');if(!ctx)throw new ProtectedImageError('unsupported-browser');
  let best:Uint8Array|null=null;
  for(const side of [Math.min(Math.max(dimensions.width,dimensions.height),2560),2048,1600,1280,960,640,480,320]){
   if(side>Math.max(dimensions.width,dimensions.height))continue;
   const scale=Math.min(1,side/Math.max(bitmap.width,bitmap.height));canvas.width=Math.max(1,Math.round(bitmap.width*scale));canvas.height=Math.max(1,Math.round(bitmap.height*scale));
   ctx.fillStyle='#fff';ctx.fillRect(0,0,canvas.width,canvas.height);ctx.drawImage(bitmap,0,0,canvas.width,canvas.height);
   for(const quality of [.9,.82,.72,.62,.5,.38]){signal?.throwIfAborted();const blob=await new Promise<Blob>((resolve,reject)=>canvas.toBlob(b=>b?resolve(b):reject(new ProtectedImageError('unsupported-image')),'image/jpeg',quality));if(blob.type!=='image/jpeg')throw new ProtectedImageError('unsupported-image');
    const candidate=new Uint8Array(await blob.arrayBuffer());if(!best||candidate.length<best.length)best=candidate;if(candidate.length<=targetBytes)return {bytes:candidate,filename:filename.replace(/\.[^.]*$/,'')+'.jpg'};
   }
  }
  if(!best)throw new ProtectedImageError('unsupported-image');return {bytes:best,filename:filename.replace(/\.[^.]*$/,'')+'.jpg'};
 }finally{bitmap.close();canvas.width=canvas.height=1;}
}
