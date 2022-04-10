namespace Epoche;

public class Keccak256Tests
{
    [Theory]
    [InlineData("", "c5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470")]
    [InlineData("depositBNB()", "42220f3419be466f213f4b3042de8080f1629750f4ad2a978c9aac1c4d15ec51")]
    [InlineData("depositAll()", "de5f62680220b9bac30b82cd3c6046aab77423e742dda8ca78b10a1921b1f21b")]
    [InlineData("transfer(address,uint256)", "a9059cbb2ab09eb219583f4a59a5d0623ade346d962bcd4e46b11da047c9049b")]
    public async Task TestCases(string input, string expected)
    {
        var hash = Keccak256.ComputeHash(input).ToLowerHex();
        Assert.Equal(expected, Keccak256.ComputeHash(input).ToLowerHex());
        Assert.Equal(expected, Keccak256.ComputeHash(Encoding.UTF8.GetBytes(input)).ToLowerHex());
        Assert.Equal(expected, (await Keccak256.ComputeHashAsync(new MemoryStream(Encoding.UTF8.GetBytes(input)))).ToLowerHex());
        Assert.Equal("0x" + expected[..8], Keccak256.ComputeEthereumFunctionSelector(input));
    }
}
