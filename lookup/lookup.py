import discord
import re
import asyncio
from typing import List, Tuple, Optional
from github import Github, Auth
from github.GithubException import GithubException
from github.ContentFile import ContentFile
from datetime import datetime
from redbot.core import commands, Config, checks
from redbot.core.bot import Red
from redbot.core.utils.chat_formatting import box
from discord.ui import Modal, TextInput



class GitHubSetupModal(Modal, title='GitHub Integration Setup'):
    token = TextInput(
        label='GitHub Token',
        placeholder='Your GitHub personal access token',
        required=True
    )
    repository = TextInput(
        label='Repository',
        placeholder='username/repository',
        required=True
    )

    async def on_submit(self, interaction: discord.Interaction):
        await interaction.response.send_message("Processing...", ephemeral=True)
        self.stop()


class SetupButton(discord.ui.View):
    def __init__(self, member):
        self.member = member
        super().__init__()
        self.modal = None

    @discord.ui.button(label='Setup', style=discord.ButtonStyle.green)
    async def setup(self, interaction: discord.Interaction, button: discord.ui.Button):
        if self.member != interaction.user:
            return await interaction.response.send_message("You cannot use this.", ephemeral=True)

        self.modal = GitHubSetupModal()
        await interaction.response.send_modal(self.modal)
        await self.modal.wait()
        self.stop()


class GitHubLookup(commands.Cog):
    """Look up GitHub files and PRs directly in Discord"""

    def __init__(self, bot: Red):
        super().__init__()
        self.bot = bot
        self.config = Config.get_conf(self, identifier=1234567890)
        default_guild = {
            "servers": {},
            "enabled_channels": []
        }
        self.config.register_guild(**default_guild)
        self.gh_instances = {}
        self.search_lock = asyncio.Lock()

    async def cog_load(self) -> None:
        """Initialize GitHub instances for all configured guilds on load"""
        for guild in self.bot.guilds:
            servers = await self.config.guild(guild).servers()
            for server_name, server_data in servers.items():
                try:
                    auth = Auth.Token(server_data['token'])
                    gh = Github(auth=auth)
                    repo_instance = gh.get_repo(server_data['repository'])
                    self.gh_instances[guild.id] = {
                        "client": gh,
                        "repo": repo_instance
                    }
                except Exception:
                    continue

    async def cog_unload(self) -> None:
        """Clean up GitHub instances on unload"""
        for instance in self.gh_instances.values():
            instance["client"].close()
        self.gh_instances.clear()

    @staticmethod
    def strip_html_comments(text: str) -> str:
        """Remove HTML comments from text."""
        if not text:
            return ""
        return re.sub(r'<!--[\s\S]*?-->', '', text)

    @staticmethod
    def get_pr_status(pr) -> Tuple[str, discord.Color]:
        """Get the status and color for a PR"""
        if pr.merged:
            return "Merged", discord.Color.purple()
        elif pr.state == "open":
            return "Open", discord.Color.green()
        else:
            return "Closed", discord.Color.red()

    @staticmethod
    def get_issue_status_color(issue) -> discord.Color:
        """Get the color for an issue based on its state and labels"""
        if issue.state == "closed":
            return discord.Color.red()
        for label in issue.labels:
            if label.name.lower() in ["bug", "critical", "urgent"]:
                return discord.Color.orange()
        return discord.Color.green()

    @staticmethod
    def extract_line_numbers(filename: str) -> Tuple[str, Optional[int], Optional[int]]:
        """Extract line numbers from filename if present."""
        match = re.match(r'(.*?):(\d+)(?:-(\d+))?$', filename)
        if match:
            file_path = match.group(1)
            start_line = int(match.group(2))
            end_line = int(match.group(3)) if match.group(3) else start_line
            return file_path, start_line, end_line
        return filename, None, None

    @staticmethod
    def get_line_range_url(url: str, start_line: int, end_line: int = None) -> str:
        """Generate GitHub URL with line number references."""
        if end_line and end_line != start_line:
            return f"{url}#L{start_line}-L{end_line}"
        return f"{url}#L{start_line}"

    @staticmethod
    def format_line_numbers(content: str, start_line: Optional[int] = None, end_line: Optional[int] = None, max_length: Optional[int] = None) -> str:
        """
        Format content with line numbers.
        If start_line and end_line are provided, only show that range.
        Otherwise, show all lines with numbers.
        If max_length is provided, truncate while preserving the requested line range.
        """
        lines = content.splitlines()

        # If no line range specified, show all lines
        if start_line is None:
            start_line = 1
            end_line = len(lines)
        elif end_line is None:
            end_line = start_line

        # Validate line numbers
        start_line = max(1, start_line)
        end_line = min(len(lines), end_line)
        if start_line > end_line:
            start_line, end_line = end_line, start_line

        # Calculate padding for line numbers
        padding = len(str(end_line))

        # If we have a max length and specific lines requested, prioritize those lines
        if max_length is not None and start_line is not None:
            # Get the specified range first
            selected_lines = lines[start_line - 1:end_line]

            # Add context before and after if space permits
            remaining_lines = max_length - sum(len(line) for line in selected_lines)
            context_lines = 3  # Number of context lines to show before and after

            if remaining_lines > 0:
                # Add lines before
                before_start = max(0, start_line - 1 - context_lines)
                before_lines = lines[before_start:start_line - 1]

                # Add lines after
                after_end = min(len(lines), end_line + context_lines)
                after_lines = lines[end_line:after_end]

                selected_lines = before_lines + selected_lines + after_lines
                start_line = before_start + 1

            # Create the numbered lines
            numbered_lines = []
            current_line = start_line
            output = ""

            for line in selected_lines:
                numbered_line = f"{current_line:{padding}d} │ {line}\n"
                if len(output) + len(numbered_line) > max_length:
                    break
                output += numbered_line
                numbered_lines.append(numbered_line.rstrip())
                current_line += 1

            return "\n".join(numbered_lines)
        else:
            # Get all specified lines
            selected_lines = lines[start_line - 1:end_line]

            # Add line numbers
            numbered_lines = [
                f"{i:{padding}d} │ {line}"
                for i, line in enumerate(selected_lines, start=start_line)
            ]

            result = "\n".join(numbered_lines)

            # Truncate if needed
            if max_length and len(result) > max_length:
                return result[:max_length - 4] + "...\n"

            return result

    @commands.group()
    @checks.admin()
    async def github(self, ctx: commands.Context):
        """Configure GitHub integration settings"""
        pass

    @github.command()
    async def setup(self, ctx: commands.Context):
        """Set up GitHub integration for this server"""
        view = SetupButton(member=ctx.author)
        await ctx.send("To set up GitHub integration, press this button.", view=view)
        await view.wait()

        if view.modal is None:
            return

        # Store in config securely
        async with self.config.guild(ctx.guild).servers() as servers:
            servers["default"] = {
                "token": view.modal.token.value,
                "repository": view.modal.repository.value
            }

        # Initialize GitHub instance
        try:
            auth = Auth.Token(view.modal.token.value)
            gh = Github(auth=auth)
            repo = gh.get_repo(view.modal.repository.value)
            self.gh_instances[ctx.guild.id] = {
                "client": gh,
                "repo": repo
            }
            await ctx.send("✅ GitHub integration configured successfully!", ephemeral=True)
        except Exception as e:
            await ctx.send(f"❌ Error configuring GitHub: {str(e)}", ephemeral=True)

    @github.command()
    async def channel(self, ctx: commands.Context, enabled: bool = True):
        """Enable/disable GitHub lookups in the current channel"""
        async with self.config.guild(ctx.guild).enabled_channels() as channels:
            if enabled and ctx.channel.id not in channels:
                channels.append(ctx.channel.id)
            elif not enabled and ctx.channel.id in channels:
                channels.remove(ctx.channel.id)

        status = "enabled" if enabled else "disabled"
        await ctx.send(f"GitHub lookups {status} for this channel")

    @github.command()
    async def status(self, ctx: commands.Context):
        """Show the current GitHub integration status"""
        servers = await self.config.guild(ctx.guild).servers()
        enabled_channels = await self.config.guild(ctx.guild).enabled_channels()

        if not servers:
            await ctx.send("❌ GitHub integration is not configured for this server.")
            return

        embed = discord.Embed(
            title="GitHub Integration Status",
            color=discord.Color.blue(),
            timestamp=datetime.utcnow()
        )

        # Show repository info
        repo_info = servers.get("default", {})
        if repo_info:
            embed.add_field(
                name="Repository",
                value=f"`{repo_info['repository']}`",
                inline=False
            )

        # Show enabled channels
        if enabled_channels:
            channel_mentions = [f"<#{channel_id}>" for channel_id in enabled_channels]
            embed.add_field(
                name="Enabled Channels",
                value="\n".join(channel_mentions) or "None",
                inline=False
            )
        else:
            embed.add_field(
                name="Enabled Channels",
                value="No channels enabled",
                inline=False
            )

        # Test connection
        if ctx.guild.id in self.gh_instances:
            embed.add_field(
                name="Connection Status",
                value="✅ Connected",
                inline=False
            )
        else:
            embed.add_field(
                name="Connection Status",
                value="❌ Not connected",
                inline=False
            )

        await ctx.send(embed=embed)

    async def find_matching_files(self, repo, filename: str) -> List[Tuple[str, ContentFile]]:
        """Find all files matching the given filename in the repository"""
        async with self.search_lock:  # Prevent multiple simultaneous searches
            matches = []
            loop = asyncio.get_running_loop()

            try:
                # First try direct path
                content = await loop.run_in_executor(
                    None,
                    lambda: repo.get_contents(filename)
                )
                if not isinstance(content, list):
                    matches.append((filename, content))
                    return matches
            except GithubException:
                pass

            if '/' in filename:  # If path is specified, don't do full search
                return matches

            # Use recursive tree search
            try:
                tree = await loop.run_in_executor(
                    None,
                    lambda: repo.get_git_tree(repo.default_branch, recursive=True)
                )

                for item in tree.tree:
                    if item.type == 'blob' and item.path.endswith(filename):
                        try:
                            content = await loop.run_in_executor(
                                None,
                                lambda: repo.get_contents(item.path)
                            )
                            matches.append((item.path, content))
                        except GithubException:
                            continue

            except GithubException as e:
                print(f"Search error: {e}")

            return matches

    @commands.Cog.listener()
    async def on_message(self, message: discord.Message):
        if message.author.bot or not message.guild:
            return

        enabled_channels = await self.config.guild(message.guild).enabled_channels()
        if message.channel.id not in enabled_channels:
            return

        gh_data = self.gh_instances.get(message.guild.id)
        if not gh_data:
            return

        repo = gh_data["repo"]

        # Look for file references [filename.cs] or [filename.cs:123] or [filename.cs:123-128]
        file_matches = re.findall(r'\[(.*?)]', message.content)
        for filename in file_matches:
            if filename.startswith('#'):  # Skip PR/issue references
                continue

            try:
                async with message.channel.typing():
                    # Extract line numbers if present
                    file_path, start_line, end_line = self.extract_line_numbers(filename)
                    matches = await self.find_matching_files(repo, file_path)

                if not matches:
                    embed = discord.Embed(
                        title="❌ File Not Found",
                        description=f"Could not find file '{file_path}' in the repository.",
                        color=discord.Color.red()
                    )
                    await message.channel.send(embed=embed)
                    continue

                if len(matches) > 1 and not '/' in file_path:
                    # Multiple matches found, show paths with GitHub links
                    embed = discord.Embed(
                        title="Multiple Files Found",
                        description="Please specify the full path to one of these files:",
                        color=discord.Color.gold()
                    )

                    if len(matches) > 10:
                        embed.description += f"\n\nShowing 10 of {len(matches)} matches"

                    for path, content in matches[:10]:
                        embed.add_field(
                            name=path,
                            value=f"[View on GitHub]({content.html_url})",
                            inline=False
                        )

                    await message.channel.send(embed=embed)
                    continue

                # Get the matching file
                if '/' in file_path:
                    match = next((m for m in matches if m[0] == file_path), None)
                else:
                    # If no path specified and only one match, use it
                    match = matches[0] if len(matches) == 1 else None

                if not match:
                    embed = discord.Embed(
                        title="❌ File Not Found",
                        description=f"Could not find exact file '{file_path}' in the repository.",
                        color=discord.Color.red()
                    )
                    await message.channel.send(embed=embed)
                    continue

                path, content = match
                file_content = await asyncio.get_event_loop().run_in_executor(
                    None,
                    lambda: content.decoded_content.decode()
                )

                max_content_length = 1900  # Leave room for Discord's formatting

                if start_line is not None:
                    # If specific lines requested, prioritize those
                    file_content = self.format_line_numbers(
                        file_content,
                        start_line,
                        end_line,
                        max_length=max_content_length
                    )
                    line_range = f" (lines {start_line}-{end_line})" if end_line and end_line != start_line else f" (line {start_line})"
                    github_url = self.get_line_range_url(content.html_url, start_line, end_line)
                else:
                    # Otherwise show beginning of file with line numbers
                    file_content = self.format_line_numbers(
                        file_content,
                        max_length=max_content_length
                    )
                    line_range = ""
                    github_url = content.html_url

                # Check if content was truncated
                original_lines_count = len(content.decoded_content.decode().splitlines())
                shown_lines_count = len(file_content.splitlines())
                if shown_lines_count < original_lines_count:
                    file_content += f"\n... (showing {shown_lines_count} of {original_lines_count} lines)"

                embed = discord.Embed(
                    title=f"📄 {path}{line_range}",
                    description=box(file_content, lang=path.split('.')[-1]),
                    color=discord.Color.blue(),
                    timestamp=datetime.utcnow()
                )
                embed.add_field(
                    name="View on GitHub",
                    value=f"[View file]({github_url})",
                    inline=False
                )
                await message.channel.send(embed=embed)

            except Exception as e:
                embed = discord.Embed(
                    title="❌ Error",
                    description=f"An error occurred: {str(e)}",
                    color=discord.Color.red()
                )
                await message.channel.send(embed=embed)

        pr_matches = re.findall(r'\[#(\d+)]', message.content)
        for ref_number in pr_matches:
            try:
                # Try to get PR first
                try:
                    pr = repo.get_pull(int(ref_number))
                    is_pr = True
                except GithubException:
                    # If PR not found, try to get issue
                    issue = repo.get_issue(int(ref_number))
                    is_pr = False

                if is_pr:
                    # Handle Pull Request
                    cleaned_body = self.strip_html_comments(pr.body)
                    status, color = self.get_pr_status(pr)

                    embed = discord.Embed(
                        title=f"PR #{pr.number} {pr.title}",
                        description=cleaned_body[:1000] if pr.body else "No description provided",
                        color=color,
                        url=pr.html_url,
                        timestamp=pr.created_at
                    )

                    if cleaned_body and len(cleaned_body) > 1000:
                        embed.description += "\n\n... (description truncated)"

                    embed.add_field(name="Status", value=status, inline=True)
                    embed.add_field(name="Author", value=pr.user.login, inline=True)
                    embed.add_field(name="Comments", value=str(pr.comments), inline=True)

                    if pr.merged:
                        embed.add_field(name="Merged by", value=pr.merged_by.login, inline=True)
                        embed.add_field(name="Merged at", value=pr.merged_at.strftime("%Y-%m-%d %H:%M UTC"),
                                        inline=True)

                else:
                    # Handle Issue
                    cleaned_body = self.strip_html_comments(issue.body)
                    color = self.get_issue_status_color(issue)

                    embed = discord.Embed(
                        title=f"Issue #{issue.number} {issue.title}",
                        description=cleaned_body[:1000] if issue.body else "No description provided",
                        color=color,
                        url=issue.html_url,
                        timestamp=issue.created_at
                    )

                    if cleaned_body and len(cleaned_body) > 1000:
                        embed.description += "\n\n... (description truncated)"

                    embed.add_field(name="Status", value=issue.state.capitalize(), inline=True)
                    embed.add_field(name="Author", value=issue.user.login, inline=True)
                    embed.add_field(name="Comments", value=str(issue.comments), inline=True)

                    if issue.labels:
                        labels = ", ".join(label.name for label in issue.labels)
                        embed.add_field(name="Labels", value=labels, inline=True)

                    if issue.assignees:
                        assignees = ", ".join(assignee.login for assignee in issue.assignees)
                        embed.add_field(name="Assignees", value=assignees, inline=True)

                await message.channel.send(embed=embed)

            except Exception as e:
                embed = discord.Embed(
                    title="❌ Error",
                    description=f"Error accessing #{ref_number}: {str(e)}",
                    color=discord.Color.red()
                )
                await message.channel.send(embed=embed)