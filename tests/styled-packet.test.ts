// @vitest-environment node
import {expect,it} from 'vitest';
import {embedStyledPacket,extractStyledPacket,styledCapacity,visualRects} from '../src/image/styled-packet';
import {protectFile,unlockProtectedFile} from '../src/index';
it.each([1,2,3])('protects reserved visual areas without altering exact data, flags %i',async flags=>{
 const bytes=new TextEncoder().encode('Exact private PDF bytes \0 🌍'),encrypted=await protectFile(bytes,'private.pdf','A long original secret stays local');
 for(const bits of [2,8] as const){const width=512,height=256,frame=new Uint8ClampedArray(width*height*4).fill(255);embedStyledPacket(frame,width,height,encrypted,bits,flags);
  for(const rect of visualRects(width,height,flags))for(let y=rect.y;y<rect.y+rect.height;y++)frame.fill(77,(y*width+rect.x)*4,(y*width+rect.x+rect.width)*4);
  const recovered=extractStyledPacket(frame,width,height)!;expect(recovered).toEqual(encrypted);expect((await unlockProtectedFile(recovered,'A long original secret stays local')).bytes).toEqual(bytes);
 }
});
it('checks exact capacity and rejects unsafe dimensions, hostile sizes and altered payload',()=>{
 const frame=new Uint8ClampedArray(512*256*4).fill(255),flags=3,bits=2,size=styledCapacity(512,256,bits,flags),bytes=new Uint8Array(size);embedStyledPacket(frame,512,256,bytes,bits,flags);expect(extractStyledPacket(frame,512,256)).toEqual(bytes);
 expect(()=>embedStyledPacket(frame,512,256,new Uint8Array(size+1),bits,flags)).toThrow();expect(()=>styledCapacity(32,16,bits,flags)).toThrow();
 expect(extractStyledPacket(new Uint8ClampedArray(32*32*4),32,32)).toBeNull();
});
