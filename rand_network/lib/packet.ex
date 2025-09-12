defmodule Packet do
  defstruct [:bits]
  @enforce_keys [:bits]

  # Of course, a real packet would have checksums, error correction, etc.
  # In the future we could maybe add fragmentation to immitate packet loss, etc.
  def make_packet(from_node_pid, to_node_pid, message) do
    # For simplicity, we will just create a binary with fixed sizes for each field, with hops starting at 0
    message_size = byte_size(message)

    %Packet{
      bits: <<from_node_pid::256, to_node_pid::256, 0::16, message_size::16, message::binary>>
    }
  end

  # Including this here for convenience, but in a real system we would likely have
  # a separate module for parsing packets
  def parse_packet(%Packet{bits: bits}) do
    <<from_node::256, to_node::256, hops::16, message_size::16,
      message::binary-size(message_size)>> = bits

    %{
      from_node: from_node,
      to_node: to_node,
      hops: hops,
      message: message
    }
  end

  # Again, in a real system this would likely be in a separate module
  def update_hops(%Packet{bits: bits} = packet) do
    <<from_node::256, to_node::256, hops::16, message_size::16,
      message::binary-size(message_size)>> = bits

    new_hops = hops + 1

    new_bits =
      <<from_node::256, to_node::256, new_hops::16, message_size::16,
        message::binary-size(message_size)>>

    %Packet{packet | bits: new_bits}
  end

  @type t :: %__MODULE__{bits: <<_::1024>>}
end
