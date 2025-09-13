defmodule RANDTest do
  use ExUnit.Case
  doctest RAND

  test "greets the world" do
    assert RAND.hello() == :world
  end

  test "spawn and traceroute" do
    {nodes, _ifaces} = RAND.spawn_network(5, 3)
    assert length(nodes) == 5

    case RAND.traceroute(nodes, 0, 4, "hi", 1_000) do
      {:ok, hops} -> assert is_integer(hops) and hops >= 0
      :timeout -> flunk("delivery timed out")
    end
  end
end
