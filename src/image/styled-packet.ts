import { MAX_PROTECTED_IMAGE_BYTES, ProtectedImageError } from '../crypto/protected-image';
const MAGIC=new TextEncoder().encode('SNAPSEALART'),HEADER=20;
export type VisualOptions={branding?:boolean;label?:string};
export type Rect={x:number;y:number;width:number;height:number};
export function visualRects(width:number,height:number,flags:number):Rect[]{
 if(width<512||height<256||flags<1||flags>3)throw new ProtectedImageError('invalid-file');
 const badgeWidth=Math.min(180,Math.floor(width/3)),badgeHeight=32,pad=8;
 const rects:Rect[]=[];
 if(flags&1)for(const y of [pad,height-pad-badgeHeight])for(const x of [pad,width-pad-badgeWidth])rects.push({x,y,width:badgeWidth,height:badgeHeight});
 if(flags&2)rects.push({x:Math.floor((width-Math.min(400,width-32))/2),y:height-96,width:Math.min(400,width-32),height:44});
 return rects;
}
export function visualFlags(options:VisualOptions){return (options.branding?1:0)|(options.label?.trim()?2:0);}
export function styledCapacity(width:number,height:number,bits:2|8,flags:number){const used=visualRects(width,height,flags).reduce((sum,r)=>sum+r.width*r.height,0);return Math.floor((width*height-used)*3*bits/8)-HEADER;}
function visit(width:number,height:number,rects:Rect[],cb:(pixel:number)=>boolean){
 for(let y=0;y<height;y++){
  const spans=rects.filter(r=>y>=r.y&&y<r.y+r.height).sort((a,b)=>a.x-b.x);let left=0;
  for(const span of [...spans,{x:width,y:0,width:0,height:0}]){for(let x=left;x<span.x;x++)if(!cb((y*width+x)*4))return;left=Math.max(left,span.x+span.width);}
 }
}
export function embedStyledPacket(frame:Uint8ClampedArray,width:number,height:number,bytes:Uint8Array,bits:2|8,flags:number){
 if(frame.length!==width*height*4||bytes.length<62||bytes.length>MAX_PROTECTED_IMAGE_BYTES||bytes.length>styledCapacity(width,height,bits,flags))throw new ProtectedImageError('too-large');
 const header=new Uint8Array(HEADER);header.set(MAGIC);header[11]=bits===8?51:52;new DataView(header.buffer).setUint32(12,bytes.length);header[16]=flags;
 const parts=8/bits,mask=(1<<bits)-1,total=(HEADER+bytes.length)*parts;let channel=0;
 visit(width,height,visualRects(width,height,flags),pixel=>{frame[pixel+3]=255;for(let c=0;c<3;c++){
  if(channel>=total)return false;const at=Math.floor(channel/parts),value=at<HEADER?header[at]:bytes[at-HEADER];frame[pixel+c]=(frame[pixel+c]&~mask)|((value>>>((parts-1-channel%parts)*bits))&mask);channel++;
 }return channel<total;});
}
export function extractStyledPacket(frame:Uint8ClampedArray,width:number,height:number):Uint8Array|null{
 const read=(index:number,bits:2|8)=>{let value=0;for(let part=0;part<8/bits;part++){const channel=index*(8/bits)+part;value=value<<bits|(frame[Math.floor(channel/3)*4+channel%3]&((1<<bits)-1));}return value;};
 const bits=([8,2] as const).find(n=>MAGIC.every((v,i)=>read(i,n)===v));if(!bits)return null;
 const invalid=()=>{throw new ProtectedImageError('invalid-file');};
 if(frame.length!==width*height*4||read(11,bits)!==(bits===8?51:52))invalid();
 const header=Uint8Array.from({length:HEADER},(_,i)=>read(i,bits)),size=new DataView(header.buffer).getUint32(12),flags=header[16];
 if(header[17]||header[18]||header[19]||size<62||size>MAX_PROTECTED_IMAGE_BYTES||size>styledCapacity(width,height,bits,flags))invalid();
 const result=new Uint8Array(size),parts=8/bits,total=(HEADER+size)*parts;let channel=0,value=0;
 visit(width,height,visualRects(width,height,flags),pixel=>{if(frame[pixel+3]!==255)invalid();for(let c=0;c<3;c++){
  if(channel>=total)return false;value=value<<bits|(frame[pixel+c]&((1<<bits)-1));channel++;if(channel%parts===0){const at=channel/parts-1;if(at>=HEADER)result[at-HEADER]=value;value=0;}
 }return channel<total;});return result;
}
