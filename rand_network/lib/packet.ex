defmodule Packet do
  defstruct [:bits]
  @enforce_keys [:bits]

  # Of course, a real packet would have checksums, error correction, etc.
  # In the future we could maybe add fragmentation to immitate packet loss, etc.
  def make_packet(from_node_pid, to_node_pid, message, opts \\ []) do
    # To safely encode PIDs and terms, we use term_to_binary. Layout:
    # <<from::binary, to::binary, hops::16, ack_to::binary, payload::binary>> with lengths prefixed
    hops = 0
    ack_to = Keyword.get(opts, :ack_to, nil)

    from_bin = :erlang.term_to_binary(from_node_pid)
    to_bin = :erlang.term_to_binary(to_node_pid)
    ack_bin = :erlang.term_to_binary(ack_to)
    payload = :erlang.term_to_binary(message)

    bits =
      <<byte_size(from_bin)::16, from_bin::binary, byte_size(to_bin)::16, to_bin::binary,
        hops::16, byte_size(ack_bin)::16, ack_bin::binary, byte_size(payload)::16,
        payload::binary>>

    %Packet{bits: bits}
  end

  # Including this here for convenience, but in a real system we would likely have
  # a separate module for parsing packets
  def parse_packet(%Packet{bits: bits}) do
    <<from_len::16, rest::binary>> = bits
    <<from_bin::binary-size(from_len), rest::binary>> = rest
    <<to_len::16, rest::binary>> = rest
    <<to_bin::binary-size(to_len), rest::binary>> = rest
    <<hops::16, rest::binary>> = rest
    <<ack_len::16, rest::binary>> = rest
    <<ack_bin::binary-size(ack_len), rest::binary>> = rest
    <<payload_len::16, payload::binary-size(payload_len)>> = rest

    %{
      from_node: :erlang.binary_to_term(from_bin),
      to_node: :erlang.binary_to_term(to_bin),
      hops: hops,
      ack_to: :erlang.binary_to_term(ack_bin),
      message: :erlang.binary_to_term(payload)
    }
  end

  # Again, in a real system this would likely be in a separate module
  def update_hops(%Packet{bits: bits} = packet) do
    <<from_len::16, rest::binary>> = bits
    <<from_bin::binary-size(from_len), rest::binary>> = rest
    <<to_len::16, rest::binary>> = rest
    <<to_bin::binary-size(to_len), rest::binary>> = rest
    <<hops::16, rest::binary>> = rest
    <<ack_len::16, rest::binary>> = rest
    <<ack_bin::binary-size(ack_len), rest::binary>> = rest
    <<payload_len::16, payload::binary-size(payload_len)>> = rest

    new_hops = hops + 1

    new_bits =
      <<from_len::16, from_bin::binary, to_len::16, to_bin::binary, new_hops::16, ack_len::16,
        ack_bin::binary, payload_len::16, payload::binary>>

    %Packet{packet | bits: new_bits}
  end

  @type t :: %__MODULE__{bits: binary}
end
