import re
import json
import random
import logging
import aiohttp
import hashlib
import asyncio
from typing import Optional, Dict, List, Any, Set, Tuple, Union
from collections import defaultdict
from urllib.parse import quote, quote_plus

import discord
from discord.ext import commands
from redbot.core import Config, commands as red_commands, checks
from redbot.core.bot import Red
from redbot.core.utils.chat_formatting import box, pagify

log = logging.getLogger("red.github")

# Regex patterns
REG_PATH = re.compile(r"\[(?:(\S+)\/\/)?(.+?)(?:(?::|#L)(\d+)(?:-L?(\d+))?)?\]", re.I)
REG_ISSUE = re.compile(r"\[(?:(\S+)#|#)?([0-9]+)\]")
REG_COMMIT = re.compile(r"\[(?:(\S+)@)?([0-9a-f]{40})\]", re.I)
REG_AUTOLABEL = re.compile(r"\[(\w+?)\]", re.I)
REG_GIT_HEADER_PAGENUM = re.compile(r"[?&]page=(\d+)[^,]+rel=\"last\"")
MD_COMMENT_RE = re.compile(r"<!--.*-->", flags=re.DOTALL)

# Constants
COLOR_GITHUB_RED = discord.Color(0xFF4444)
COLOR_GITHUB_GREEN = discord.Color(0x6CC644)
COLOR_GITHUB_PURPLE = discord.Color(0x6E5494)
MAX_BODY_LENGTH = 500
MAX_COMMIT_LENGTH = 67
GITHUB_ISSUE_MAX_MESSAGES = 5


class GitHub(red_commands.Cog):
    """GitHub integration for Red-Discord bot"""

    def __init__(self, bot: Red):
        self.bot = bot
        self.config = Config.get_conf(self, identifier=1234567890, force_registration=True)
        
        default_global = {
            "token": None,
        }
        
        default_guild = {
            "repos": [],  # List of repo configs
        }
        
        self.config.register_global(**default_global)
        self.config.register_guild(**default_guild)
        
        self.session: Optional[aiohttp.ClientSession] = None
        self.cache: Dict[Tuple[str, str, Optional[str]], Tuple[Any, str]] = {}

    async def cog_load(self):
        """Initialize the cog"""
        token = await self.config.token()
        self._init_session(token)

    async def cog_unload(self):
        """Cleanup when cog is unloaded"""
        if self.session:
            await self.session.close()

    def _init_session(self, token: Optional[str]):
        """Initialize or reset the session with a token"""
        if self.session:
            pass

        headers = {
            "User-Agent": "Red-DiscordBot GitHub Cog",
            "Accept": "application/vnd.github.v3+json",
        }
        
        if token:
            headers["Authorization"] = f"token {token}"
            
        self.session = aiohttp.ClientSession(headers=headers)

    def github_url(self, sub: str) -> str:
        """Construct GitHub API URL"""
        return f"https://api.github.com{sub}"

    def get_color_from_extension(self, filename: str) -> discord.Color:
        """
        Generate a consistent color based on file extension
        Replaces 'colorhash' dependency to keep the cog lightweight
        """
        try:
            ext = filename.split(".")[-1]
        except IndexError:
            ext = filename
            
        # Use MD5 of extension to get a consistent hash
        hash_object = hashlib.md5(ext.encode())
        hex_dig = hash_object.hexdigest()
        # Take first 6 chars for RGB
        return discord.Color(int(hex_dig[:6], 16))

    async def get_github_object(
        self, 
        url: str, 
        *, 
        params: Optional[Dict[str, str]] = None, 
        accept: Optional[str] = None
    ) -> Any:
        """Fetch object from GitHub API with caching"""
        if not self.session:
            raise RuntimeError("GitHub session not initialized.")
        
        log.debug(f"Fetching GitHub object at URL {url}...")
        
        paramstr = str(params)
        cache_key = (url, paramstr, accept)
        
        # Check cache
        if cache_key in self.cache:
            contents, date = self.cache[cache_key]
            headers = {"If-Modified-Since": date}
            if accept:
                headers["Accept"] = accept
            
            async with self.session.get(url, headers=headers, params=params) as response:
                if response.status == 304:
                    return contents
                if response.status == 200:
                    # Update cache if 200
                    contents = await response.json()
                    if "Last-Modified" in response.headers:
                        self.cache[cache_key] = (contents, response.headers["Last-Modified"])
                    return contents
        
        headers = {}
        if accept:
            headers["Accept"] = accept
            
        async with self.session.get(url, params=params, headers=headers) as response:
            if response.status != 200:
                txt = await response.text()
                raise Exception(f"GitHub API returned {response.status}: {txt}")

            contents = await response.json()
            if "Last-Modified" in response.headers:
                self.cache[cache_key] = (contents, response.headers["Last-Modified"])

            return contents

    def format_desc(self, desc: str) -> str:
        """Format description by removing comments and truncating"""
        res = MD_COMMENT_RE.sub("", desc)
        if len(res) > MAX_BODY_LENGTH:
            res = res[:MAX_BODY_LENGTH] + "..."
        return res

    def is_repo_valid_for_command(
        self, 
        repo_config: Dict[str, Any], 
        channel: discord.TextChannel, 
        prefix: Optional[str]
    ) -> bool:
        """Check if a repo config is valid for the given channel and prefix"""
        repo_prefix = repo_config.get("prefix")
        repo_prefix_required = repo_config.get("prefix_required", True)
        repo_prefix_whitelist = repo_config.get("prefix_whitelist", [])

        if str(channel.id) in repo_prefix_whitelist:
            repo_prefix_required = False

        if prefix is not None and repo_prefix != prefix:
            return False

        if prefix is None and repo_prefix_required:
            return False

        return True

    async def post_embedded_issue_or_pr(
        self, 
        channel: discord.TextChannel, 
        repo: str, 
        issueid: int, 
        sender_data: Optional[Dict[str, Any]] = None
    ) -> None:
        """Post an embedded issue or PR"""
        url = self.github_url(f"/repos/{repo}/issues/{issueid}")
        try:
            content = await self.get_github_object(url)
        except Exception as e:
            log.error(f"Failed to fetch issue {issueid}: {e}")
            await channel.send(f"⚠️ Error fetching `#{issueid}` from `{repo}`: {e}")
            return

        # Check if it's a PR
        is_pr = content.get("pull_request") is not None
        prcontent = {}
        
        if is_pr:
            try:
                pr_url = self.github_url(f"/repos/{repo}/pulls/{issueid}")
                prcontent = await self.get_github_object(pr_url)
            except Exception as e:
                log.error(f"Failed to fetch PR details for {issueid}: {e}")
                # Fallback to issue content if PR fetch fails
                is_pr = False

        # Create embed
        embed = discord.Embed()
        emoji = ""
        
        # LOGIC FIX HERE
        if content["state"] == "open":
            # Open is always Green (whether Issue or PR)
            emoji = "<:open:1446291254911701164>" 
            embed.color = COLOR_GITHUB_GREEN
        elif is_pr and prcontent.get("merged"):
            # Merged PR is Purple
            emoji = "<:merge:1446291518661984357>"
            embed.color = COLOR_GITHUB_PURPLE
        else:
            # Closed (Issue or unmerged PR) is Red
            emoji = "<:closed:1446291305025241200>"
            embed.color = COLOR_GITHUB_RED

        embed.title = f"{emoji} {content['title']}"
        embed.url = content["html_url"]
        embed.set_footer(
            text=f"{repo}#{content['number']} by {content['user']['login']}", 
            icon_url=content["user"]["avatar_url"]
        )

        if sender_data:
            embed.set_author(
                name=sender_data["login"], 
                url=sender_data["html_url"], 
                icon_url=sender_data["avatar_url"]
            )

        # Format description
        body = self.format_desc(content["body"] or "")
        embed.description = body + "\n"

        # Get reactions
        try:
            reactions = await self.get_github_object(
                f"{url}/reactions?per_page=100", 
                accept="application/vnd.github.squirrel-girl-preview+json"
            )
            all_reactions = defaultdict(int)
            for react in reactions:
                all_reactions[react["content"]] += 1

            reaction_text = ""
            if all_reactions.get("+1"):
                reaction_text += f"👍 {all_reactions['+1']}"
            if all_reactions.get("-1"):
                if reaction_text:
                    reaction_text += "   "
                reaction_text += f"👎 {all_reactions['-1']}"
            
            if reaction_text:
                embed.description += reaction_text + "\n"
        except Exception as e:
            log.warning(f"Failed to fetch reactions: {e}")

        # PR-specific info
        if is_pr:
            try:
                merge_sha = prcontent["head"]["sha"]
                check_content = await self.get_github_object(
                    self.github_url(f"/repos/{repo}/commits/{merge_sha}/check-runs"),
                    accept="application/vnd.github.antiope-preview+json"
                )

                checks = ""
                for check in check_content["check_runs"]:
                    status = "❓"
                    if check["status"] == "queued":
                        status = "😴"
                    elif check["status"] == "in_progress":
                        status = "🏃"
                    elif check["status"] == "completed":
                        conclusion = check.get("conclusion", "unknown")
                        status_map = {
                            "neutral": "😐",
                            "success": "😄",
                            "failure": "😭",
                            "cancelled": "🛑",
                            "timed_out": "⌛",
                            "action_required": "🚧"
                        }
                        status = status_map.get(conclusion, "❓")

                    checks += f"`{check['name']} {status}`\n"

                if checks:
                    embed.add_field(name="Checks", value=checks)

                if not prcontent.get("mergeable", True) and content["state"] == "open":
                    embed.add_field(name="Status", value="🚨 CONFLICTS 🚨")
            except Exception as e:
                log.warning(f"Failed to fetch PR checks: {e}")

        await channel.send(embed=embed)

    @red_commands.group()
    @checks.admin_or_permissions(manage_guild=True)
    async def ghset(self, ctx: red_commands.Context):
        """Configure GitHub integration"""
        pass

    @ghset.command(name="token")
    async def set_token(self, ctx: red_commands.Context, potential_token: Optional[str] = None):
        """
        Set the GitHub API token via DM.
        
        Run this command without arguments to start the DM process.
        """
        # Security: If they accidentally provided the token in the command, delete it
        if potential_token and ctx.guild:
            try:
                await ctx.message.delete()
            except (discord.Forbidden, discord.NotFound):
                pass
            await ctx.send(f"{ctx.author.mention} ⚠️ Please do not provide the token directly in the channel! I've initiated a DM session for you.", delete_after=10)
        
        # Determine where to interact
        if ctx.guild:
            await ctx.send(f"{ctx.author.mention}, check your DMs to set the GitHub token.")
            
        try:
            dm_channel = await ctx.author.create_dm()
        except discord.Forbidden:
            if ctx.guild:
                await ctx.send("❌ I couldn't send you a DM. Please enable DMs from server members.")
            return

        # Prompt in DM
        msg_content = (
            "Please paste your GitHub Personal Access Token below.\n"
            "**Requirements:**\n"
            "- It often starts with `ghp_` or `github_pat_`.\n"
            "- This request will time out in 60 seconds.\n\n"
            "You can generate a token here: <https://github.com/settings/tokens>\n"
            "Type `cancel` to stop."
        )
        try:
            await dm_channel.send(msg_content)
        except discord.Forbidden:
            return

        # Wait function
        def check(m):
            return m.author == ctx.author and m.channel == dm_channel

        try:
            msg = await self.bot.wait_for("message", check=check, timeout=60)
        except asyncio.TimeoutError:
            await dm_channel.send("❌ Operation timed out. Please try `.ghset token` again.")
            return

        response = msg.content.strip()
        
        if response.lower() == "cancel":
            await dm_channel.send("Operation cancelled.")
            return

        # Set the token
        await self.config.token.set(response)
        
        # Reinitialize session
        if self.session:
            await self.session.close()
        
        self._init_session(response)
        
        await dm_channel.send("✅ GitHub token set successfully!")

    @ghset.command(name="addrepo")
    async def add_repo(
        self, 
        ctx: red_commands.Context, 
        repo: str, 
        prefix: str, 
        prefix_required: bool = True
    ):
        """Add a repository configuration
        
        Example: [p]ghset addrepo owner/repo gh true
        """
        repo = self._parse_repo_path(repo)
        
        if not repo or "/" not in repo:
            await ctx.send("❌ Invalid repository format. Use `owner/repo`.")
            return
        
        # Verify the repo exists
        try:
            url = self.github_url(f"/repos/{repo}")
            await self.get_github_object(url)
        except Exception as e:
            await ctx.send(f"❌ Could not access repository `{repo}`. Make sure it exists and the token has access.\nError: {str(e)}")
            return
        
        async with self.config.guild(ctx.guild).repos() as repos:
            if any(r["repo"] == repo for r in repos):
                await ctx.send(f"⚠️ Repository `{repo}` is already configured!")
                return
            
            repo_config = {
                "repo": repo,
                "prefix": prefix,
                "prefix_required": prefix_required,
                "branch": "master", # Default branch
                "prefix_whitelist": []
            }
            repos.append(repo_config)
        
        await ctx.send(f"✅ Added repo `{repo}` with prefix `{prefix}`")

    @ghset.command(name="setbranch")
    async def set_branch(self, ctx: red_commands.Context, repo_name: str, branch: str):
        """Set the default branch for file lookups"""
        repo_name = self._parse_repo_path(repo_name)
        
        async with self.config.guild(ctx.guild).repos() as repos:
            for r in repos:
                if r["repo"] == repo_name:
                    r["branch"] = branch
                    await ctx.send(f"✅ Branch for `{repo_name}` set to `{branch}`.")
                    return
        
        await ctx.send(f"❌ Repo `{repo_name}` not configured.")
    
    def _parse_repo_path(self, repo: str) -> str:
        """Parse a repo path from various formats"""
        if repo.startswith("https://github.com/"):
            repo = repo.replace("https://github.com/", "")
        elif repo.startswith("github.com/"):
            repo = repo.replace("github.com/", "")
        
        repo = repo.rstrip("/")
        if repo.endswith(".git"):
            repo = repo[:-4]
        
        return repo

    @ghset.command(name="removerepo")
    async def remove_repo(self, ctx: red_commands.Context, repo: str):
        """Remove a repository configuration"""
        repo = self._parse_repo_path(repo)
        
        async with self.config.guild(ctx.guild).repos() as repos:
            original_count = len(repos)
            repos[:] = [r for r in repos if r["repo"] != repo]
            
            if len(repos) == original_count:
                await ctx.send(f"❌ Repository `{repo}` not found in configuration.")
                return
        
        await ctx.send(f"✅ Removed repo `{repo}`")

    @ghset.command(name="listrepos")
    async def list_repos(self, ctx: red_commands.Context):
        """List configured repositories"""
        repos = await self.config.guild(ctx.guild).repos()
        
        if not repos:
            await ctx.send("No repositories configured for this server.")
            return
        
        embed = discord.Embed(title="Configured Repositories", color=discord.Color.blue())
        for repo in repos:
            value = f"Prefix: `{repo['prefix']}`\n"
            value += f"Prefix Required: {repo['prefix_required']}\n"
            value += f"Branch: {repo.get('branch', 'master')}"
            embed.add_field(name=repo['repo'], value=value, inline=False)
        
        await ctx.send(embed=embed)

    @red_commands.command()
    async def giveissue(self, ctx: red_commands.Context, prefix: Optional[str] = None):
        """Get a random issue from a configured repository"""
        repos = await self.config.guild(ctx.guild).repos()
        
        if not repos:
            await ctx.send("❌ No repositories configured.")
            return

        await ctx.message.add_reaction("⏳")

        for repo_config in repos:
            repo = repo_config["repo"]

            if prefix and repo_config.get("prefix") != prefix:
                continue
            
            if not prefix and repo_config.get("prefix_required", True):
                continue

            try:
                url = self.github_url(f"/repos/{repo}/issues")
                params = {"state": "open", "per_page": 30}
                
                # Check header for pagination
                async with self.session.get(url, params=params) as page_get:
                    if page_get.status != 200:
                        continue
                    
                    link_header = page_get.headers.get("Link", "")
                    
                    if not link_header:
                        issue_page = await page_get.json()
                        if not issue_page: continue
                        rand_issue = random.choice(issue_page)["number"]
                        await self.post_embedded_issue_or_pr(ctx.channel, repo, rand_issue)
                        await ctx.message.remove_reaction("⏳", ctx.me)
                        await ctx.message.add_reaction("👍")
                        return
                    
                    lastpagematch = REG_GIT_HEADER_PAGENUM.search(link_header)
                    if lastpagematch:
                        maxpage = int(lastpagematch.group(1))
                        pagenum = random.randrange(1, maxpage + 1)
                        issue_page = await self.get_github_object(url, params={"page": str(pagenum), "state": "open", "per_page": 30})
                    else:
                        issue_page = await page_get.json()
                    
                    if not issue_page: continue

                    rand_issue = random.choice(issue_page)["number"]
                    await self.post_embedded_issue_or_pr(ctx.channel, repo, rand_issue)
                    
                    await ctx.message.remove_reaction("⏳", ctx.me)
                    await ctx.message.add_reaction("👍")
                    return

            except Exception:
                continue

        await ctx.message.remove_reaction("⏳", ctx.me)
        await ctx.send("❌ No random issue found.")

    async def handle_file_lookup(self, message: discord.Message, repos: List[Dict[str, Any]]) -> bool:
        """Handle file path lookups [path/to/file.py]"""
        if not REG_PATH.search(message.content):
            return False

        # Parse all matches first
        prefixes = [None]
        paths = []
        
        for match in REG_PATH.finditer(message.content):
            prefix = match.group(1)
            if prefix is not None and prefix not in prefixes:
                prefixes.append(prefix)
            
            path_str = match.group(2).lower()
            if len(path_str) <= 3: # Ignore short paths
                continue
                
            rooted = False
            if path_str.startswith("^"):
                path_str = path_str[1:]
                rooted = True
                
            linestart = match.group(3)
            lineend = match.group(4)
            
            paths.append((path_str, linestart, lineend, rooted, prefix))

        if not paths:
            return False

        # Output structure: repo_name -> list of (title, url)
        output = defaultdict(list)
        color = None

        for repo_config in repos:
            # Check if this repo matches any of the prefixes found
            if not any(self.is_repo_valid_for_command(repo_config, message.channel, p) for p in prefixes):
                continue

            repo = repo_config["repo"]
            branchname = repo_config.get("branch", "master")

            try:
                # Get Branch SHA
                url = self.github_url(f"/repos/{repo}/branches/{branchname}")
                branch_data = await self.get_github_object(url)
                branch_sha = branch_data['commit']['sha']

                # Get Tree (Recursive)
                tree_url = self.github_url(f"/repos/{repo}/git/trees/{branch_sha}")
                tree_data = await self.get_github_object(tree_url, params={"recursive": "1"})
                
                if "tree" not in tree_data:
                    continue

                for search_path, linestart, lineend, rooted, match_prefix in paths:
                    if not self.is_repo_valid_for_command(repo_config, message.channel, match_prefix):
                        continue

                    # Search tree
                    for file_node in tree_data["tree"]:
                        node_path = file_node["path"]
                        node_path_lower = node_path.lower()
                        
                        match = False
                        if rooted:
                            if node_path_lower.startswith(search_path):
                                match = True
                        else:
                            if node_path_lower.endswith(search_path):
                                match = True
                                
                        if match:
                            # Construct URL
                            file_url_part = quote(node_path)
                            if linestart:
                                file_url_part += f"#L{linestart}"
                                if lineend:
                                    file_url_part += f"-L{lineend}"
                            
                            full_url = f"https://github.com/{repo}/blob/{branchname}/{file_url_part}"
                            
                            title = node_path
                            if lineend:
                                title += f" lines {linestart}-{lineend}"
                            elif linestart:
                                title += f" line {linestart}"
                                
                            output[repo].append((title, full_url))
                            
                            # Determine color based on extension of the found file
                            this_color = self.get_color_from_extension(node_path)
                            if color is None:
                                color = this_color
                            elif color != this_color:
                                color = discord.Color.default() # Mixed types
            except Exception as e:
                log.debug(f"Error fetching tree for {repo}: {e}")
                continue

        if not output:
            return False

        embed = discord.Embed()
        if color:
            embed.color = color

        for repo, hits in output.items():
            value = ""
            count = 0
            # Limit hits per repo to avoid hitting embed limits
            for title, url in hits:
                count += 1
                entry = f"[`{title}`]({url})\n"
                if len(value) + len(entry) > 1000:
                    value += f"...and {len(hits) - count + 1} more."
                    break
                value += entry
            
            embed.add_field(name=repo, value=value, inline=False)

        await message.channel.send(embed=embed)
        return True

    @red_commands.Cog.listener()
    async def on_message_without_command(self, message: discord.Message):
        """Listen for issue/PR references and file paths in messages"""
        if message.author.bot or not message.guild:
            return

        if not await self.bot.allowed_by_whitelist_blacklist(message.author):
            return

        repos = await self.config.guild(message.guild).repos()
        if not repos:
            return

        # 1. Try File Lookup
        if await self.handle_file_lookup(message, repos):
            return

        messages_sent = 0

        # 2. Handle Issue References
        for repo_config in repos:
            repo = repo_config["repo"]

            # Issues
            for match in REG_ISSUE.finditer(message.content):
                prefix = match.group(1)
                
                if not self.is_repo_valid_for_command(repo_config, message.channel, prefix):
                    continue

                issueid = int(match.group(2))
                
                if not prefix and issueid < 30:
                    continue

                await self.post_embedded_issue_or_pr(message.channel, repo, issueid)
                
                messages_sent += 1
                if messages_sent >= GITHUB_ISSUE_MAX_MESSAGES:
                    return

            # Commits
            for match in REG_COMMIT.finditer(message.content):
                prefix = match.group(1)

                if not self.is_repo_valid_for_command(repo_config, message.channel, prefix):
                    continue

                sha = match.group(2)
                url = self.github_url(f"/repos/{repo}/git/commits/{sha}")
                
                try:
                    commit = await self.get_github_object(url)
                except Exception:
                    continue

                split = commit["message"].split("\n")
                title = split[0]
                desc = "\n".join(split[1:])
                
                if len(desc) > MAX_BODY_LENGTH:
                    desc = desc[:MAX_BODY_LENGTH] + "..."

                embed = discord.Embed()
                embed.set_footer(text=f"{repo} {sha} by {commit['author']['name']}")
                embed.url = commit["html_url"]
                embed.title = title
                embed.description = self.format_desc(desc)

                await message.channel.send(embed=embed)

                messages_sent += 1
                if messages_sent >= GITHUB_ISSUE_MAX_MESSAGES:
                    return

async def setup(bot: Red):
    """Setup function for Red-Discord bot"""
    cog = GitHub(bot)
    await bot.add_cog(cog)