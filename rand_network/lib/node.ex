# A RAND network node, implemented as a GenServer.
# Each node maintains a table describing:
# - output/input links to other nodes
# - a directory of "known" nodes in the network (we're only connected to $NUM_NODE_CONNECTIONS)
# - the number of hops taken from said node to reach this node

# The state of this GenServer includes:
# - a list of hardware links to other nodes (implemented as Agents)
# - a stack of messages to process
# - a map of known nodes and their hop counts

# The state of this GenServer looks like:
# %{
#   node_map: %{{node_id, link_id} => hop_count, ...} # This functions as a 2-key map
# }

# Note that we **DO NOT** need to implement a stack, given that Erlang processes implement a message queue by default.
# As well, according to Elixir docs, we should not implement a receive loop for our GenServers.

defmodule RAND.Node do
  use GenServer

  # Client

  def start_link(default) when is_list(default) do
    GenServer.start_link(__MODULE__, default)
  end

  def push_packet(node_pid, packet) do
    GenServer.call(node_pid, {:incoming_packet, packet})
  end

  # Server (callbacks)

  @impl true
  def init(network_interface_pids) do
    state = %{
      name: self(),
      # Map of {from_node, link_id} => hops
      node_map: %{},
      # List of pids of HardwareLink processes
      interface_pids: network_interface_pids,
      # Address of this node
      address: nil
    }

    {:ok, state}
  end

  @impl true
  def handle_call({:incoming_packet, packet}, {from_local_interface_pid, _call}, state) do
    %{
      from_node: from_node_pid,
      to_node: to_node_pid,
      hops: hops,
      message: _message,
      ack_to: ack_to,
      ttl: ttl # default 64
    } =
      parse_packet(packet)

    state = update_node_map(state, from_node_pid, from_local_interface_pid, hops + 1)

    if hops >= ttl do
      {:reply, :ok, state} # kill the packet
    else

    if is_this_node?(to_node_pid) do
      # The traceroute function will create a Packet that incorporates a trace
      # tuple as its message - {{:trace, list_of_addresses}, {:payload, payload}}.
      # As the packet passes through the nodes, we append an address to the trace list.
      annotated = annotate_trace(packet, state)

      # We parse the packet to get the message and extract the payload (granted there's a bit of
      # duplication here we should get rid of).
      #TODO: get rid of this duplication, parsing three times by now is idiotic.
      parsed_for_ack = parse_packet(annotated)
      IO.puts("Message reached destination: #{inspect(parsed_for_ack)}")

      if ack_to do
        # This is hacky, but we essentially bypass the whole node mesh and
        # send the confirmation back to the original process that requested the traceroute.
        send(ack_to, {:delivered, self(), hops, parsed_for_ack})
      end

      # We route the ACK back to the source node so it can learn the distance to us, if ack_to is present.
      maybe_route_ack(parsed_for_ack, state)

      {:reply, :ok, state}
    else
      # Otherwise, we forward the packet to the next node in the mesh.
      # This function will check to see if an interface is busy, and if so, it will try the next best route.
      # If no route is found, it will send the packet out of a random link.
      try_forward_with_retry(state, to_node_pid, from_local_interface_pid, packet)

      {:reply, :ok, state}
    end
  end
end

  # Address calls (grouped with other handle_call clauses)
  @impl true
  def handle_call({:register_address, address}, _from, state) do
    {:reply, :ok, %{state | address: address}}
  end
  @impl true
  def handle_call(:get_address, _from, state) do
    {:reply, state.address, state}
  end


  # Helper functions

  @spec forward_packet(pid(), any()) :: :ok
  def forward_packet(interface_pid, packet) do
    spawn(fn -> HardwareLink.transmit_packet(interface_pid, packet) end)
    :ok
  end

  @spec parse_packet(Packet.t()) :: map()
  def parse_packet(packet), do: Packet.parse_packet(packet)

  # TTL extraction now handled via Packet header

  # If the message is a trace tuple, append this node's address and return updated packet
  defp annotate_trace(packet, %{address: nil}), do: packet
  defp annotate_trace(packet, %{address: address}) do
    case Packet.parse_packet(packet) do
      %{message: {:trace, path, payload}} when is_list(path) ->
        Packet.update_message(packet, {:trace, path ++ [address], payload})
      %{message: {:trace, path}} when is_list(path) ->
        Packet.update_message(packet, {:trace, path ++ [address]})
      _ ->
        packet
    end
  end

  # Optionally route an ACK packet back through the mesh to the source so nodes learn distances to us
  defp maybe_route_ack(%{from_node: src, message: {:ack_request, _}}, state) when is_pid(src) do
    ack = Packet.make_packet(self(), src, {:route_ack, state.address}, ack_to: nil)
    try_forward_with_retry(state, src, nil, ack)
  end
  defp maybe_route_ack(_parsed, _state), do: :ok

  # Address helpers
  def register_address(node_pid, address), do: GenServer.call(node_pid, {:register_address, address})
  def get_address(node_pid), do: GenServer.call(node_pid, :get_address)


  @spec is_this_node?(pid()) :: boolean
  def is_this_node?(to_node) do
    to_node == self()
  end

  # Update the node map with the minimum hops to reach a given node via a given link
  @spec update_node_map(
          state :: map(),
          from_node :: pid(),
          link_id :: pid(),
          hops :: non_neg_integer()
        ) :: map()
  def update_node_map(state, from_node, link_id, hops) do
    updated_node_map =
      Map.update(state.node_map, {from_node, link_id}, hops, fn existing_hops ->
        min(existing_hops, hops)
      end)

    %{state | node_map: updated_node_map}
  end

  # Find the fastest route to a given node,
  # returning a tuple of {{node, link}, hops} or nil if no route exists
  @spec fastest_route(state :: map(), to_node :: pid()) ::
          {{pid(), pid()}, non_neg_integer()} | nil
  def fastest_route(state, to_node) do
    state.node_map
    |> Enum.filter(fn {{node, _link}, _hops} -> node == to_node end)
    |> Enum.min_by(fn {_key, hops} -> hops end, fn -> nil end)
  end

  # Like fastest_route/2, but exclude a specific link (e.g., the incoming interface)
  def best_route_excluding(state, to_node, exclude_link) do
    state.node_map
    |> Enum.filter(fn {{node, link}, _hops} -> node == to_node and link != exclude_link end)
    |> Enum.min_by(fn {_key, hops} -> hops end, fn -> nil end)
  end

  # Try best route; if busy, try next best, etc. Falls back to random if none succeed.
  defp try_forward_with_retry(state, to_node_pid, exclude_link, packet) do
    candidate_links =
      state.node_map
      |> Enum.filter(fn {{node, link}, _} -> node == to_node_pid and link != exclude_link end)
      |> Enum.sort_by(fn {{_, _}, hops} -> hops end)
      |> Enum.map(fn {{_, link}, _} -> link end)

    annotated = annotate_trace(packet, state)
    updated = Packet.update_hops(annotated)

    case try_links_sequentially(candidate_links, updated) do
      :ok -> :ok
      :none ->
        others = state.interface_pids |> Enum.filter(fn ip -> ip != exclude_link end)
        if others == [] do
          :ok
        else
          iface = Enum.random(others)
          spawn(fn -> HardwareLink.try_transmit(iface, updated) end)
          :ok
        end
    end
  end

  defp try_links_sequentially([], _packet), do: :none
  defp try_links_sequentially([link | rest], packet) do
    case HardwareLink.try_transmit(link, packet) do
      :ok -> :ok
      :busy -> try_links_sequentially(rest, packet)
      :no_peer -> try_links_sequentially(rest, packet)
    end
  end
end
