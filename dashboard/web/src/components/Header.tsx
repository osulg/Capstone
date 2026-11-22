// 로고: src/assets/logo.svg (또는 logo.png) 를 넣으면 자동으로 쓴다. 없으면 '로고' 자리표시를 보여준다.
// 빌드 때 파일 이름에 해시가 붙어 dist/assets/ 로 들어가므로 서버의 /assets 경로로 그대로 제공된다.
const logos = import.meta.glob<string>("../assets/logo.{svg,png}", { eager: true, import: "default" });
const logoSrc = logos["../assets/logo.svg"] ?? logos["../assets/logo.png"];

export default function Header() {
  return (
    <div className="titlebar">
      {logoSrc
        ? <img className="logo-img" src={logoSrc} alt="HoldFS 로고" />
        : <div className="logo">로고</div>}
      <h1>HoldFS Dashboard</h1>
      <span>FUSE 기반 악성코드 탐지·대응 현황</span>
    </div>
  );
}
