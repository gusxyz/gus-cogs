from redbot.core.bot import Red
from .lookup import GitHubLookup

async def setup(bot: Red) -> None:
    await bot.add_cog(GitHubLookup(bot))