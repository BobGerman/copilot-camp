<div class="cc-lab-toc b-path">
  <img src="/copilot-camp/assets/images/path-icons/B-path-heading.png"></img>
  <div>
    <p>Do these labs if you want to build a Custom engine agent with custom AI model and orchestration using Azure OpenAI and Teams AI library</p>
    <ul>
      <li><a href="/copilot-camp/pages/custom-engine/00-prerequisites/">B0 - Setup</a></li>
      <li><a href="/copilot-camp/pages/custom-engine/01-custom-engine-agent/">B1 - First custom engine agent</a></li>
      <li><a href="/copilot-camp/pages/custom-engine/02-rag/">B2 - Index your data in Azure AI Search</a></li>
      <li><a href="/copilot-camp/pages/custom-engine/03-powered-by-ai/">B3 - Enhance the user experience</a></li>
      <li><a href="/copilot-camp/pages/custom-engine/04-authentication/">B4 - Add single sign on authentication</a></li>
      <li><a href="/copilot-camp/pages/custom-engine/05-actions/">B5 - Add actions to handle complex tasks</a></li>
    </ul>
  </div>
</div>

<script>
(() => {
// This script decorates the table of contents with a "you are here" indicator.
const toc = document.getElementsByClassName('cc-lab-toc');
for (const div of toc) {
    const lis = div.querySelectorAll('li');
    for (const li of lis) {
        const anchor = li.querySelector('a');
        if (location.href.includes(anchor.href)) {
            const span = document.createElement("span");
            span.innerHTML = "YOU&nbsp;ARE&nbsp;HERE";
            li.appendChild(span);
        }
    }    
}
})();
</script>