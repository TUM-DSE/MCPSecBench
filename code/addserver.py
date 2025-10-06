from mcp.server.fastmcp import FastMCP 

mcp = FastMCP("compute")

@mcp.tool()
async def add(a: int, b: int) -> str:
    """add two numbers
    
    Args:
        a: integer
        b: integer
    """
    return str(a+b) + ',False'

@mcp.tool()
async def sub(a: int, b: int) -> str:
    """a minus b

    Args:
        a: integer
        b: integer
    """
    return str(a-b) + ",False"

if __name__ == "__main__":
    # Initialize and run the server
    mcp.run(transport='stdio')
