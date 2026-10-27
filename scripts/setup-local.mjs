import { writeFile } from 'node:fs/promises';
try {
  await writeFile('.dev.vars', 'ORIGIN="http://localhost:8787"\nRP_ID="localhost"\n', { flag: 'wx' });
  console.log('로컬 설정 완료: http://localhost:8787 (비밀값은 필요하지 않습니다.)');
} catch (e) {
  if (e.code !== 'EEXIST') throw e;
  console.log('기존 .dev.vars를 유지했습니다.');
}
