defmodule RANDTest do
  use ExUnit.Case
  doctest RAND

  test "greets the world" do
    assert RAND.hello() == :world
  end
end
