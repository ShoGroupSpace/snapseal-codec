import { visualRects,type VisualOptions,visualFlags } from './styled-packet';
const logoURL=new URL('../assets/brand-mark.png',import.meta.url).href;
/** Public artwork is painted only in regions excluded from the lossless packet. */
export async function visualOverlay(width:number,height:number,options:VisualOptions){
 const flags=visualFlags(options),rects=visualRects(width,height,flags),canvas=document.createElement('canvas');canvas.width=width;canvas.height=height;
 const ctx=canvas.getContext('2d',{willReadFrequently:true});if(!ctx)throw new Error('canvas');let logo:ImageBitmap|undefined;
 try{
  if(options.branding){const response=await fetch(logoURL,{credentials:'omit'});if(!response.ok)throw new Error('logo');logo=await createImageBitmap(await response.blob());}
  const cleanLabel=(options.label??'').replace(/[\u0000-\u001f\u007f\u202a-\u202e\u2066-\u2069]/g,' ').trim().slice(0,48);
  const plates=rects.map((r,index)=>{
   ctx.fillStyle='#f8faf5';ctx.fillRect(r.x,r.y,r.width,r.height);ctx.strokeStyle='#9aaca2';ctx.strokeRect(r.x+.5,r.y+.5,r.width-1,r.height-1);ctx.fillStyle='#1d2927';
   if(options.branding&&index<4){ctx.drawImage(logo!,r.x+5,r.y+4,24,24);ctx.font='bold 16px sans-serif';ctx.textAlign='left';ctx.fillText('SnapSeal App',r.x+35,r.y+21,r.width-39);}
   else{ctx.font='16px sans-serif';ctx.textAlign='center';const chars=Array.from(cleanLabel);let line='';const lines:string[]=[];for(const char of chars){if(ctx.measureText(line+char).width>r.width-20){lines.push(line);line=char;}else line+=char;}if(line)lines.push(line);for(const [i,text]of lines.slice(0,2).entries())ctx.fillText(text,r.x+r.width/2,r.y+18+i*18,r.width-20);}
   return {rect:r,pixels:ctx.getImageData(r.x,r.y,r.width,r.height).data};
  });
  return (frame:Uint8ClampedArray)=>{for(const{rect:r,pixels}of plates)for(let y=0;y<r.height;y++)frame.set(pixels.subarray(y*r.width*4,(y+1)*r.width*4),((r.y+y)*width+r.x)*4);};
 }finally{logo?.close();canvas.width=canvas.height=1;}
}
