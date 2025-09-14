defmodule RAND do
  @moduledoc """
  Documentation for `RAND`.
  """

  @doc """
  Spawn a random mesh network with the given number of nodes and interfaces per node.

  Returns a list of node pids and a flat list of hardware link pids.
  """
  def spawn_network(num_nodes, interfaces_per_node)
      when num_nodes > 1 and interfaces_per_node > 0 do
    # 1) Create all hardware links (one per interface)
    total_links = num_nodes * interfaces_per_node

    link_pids =
      for _ <- 1..total_links do
        {:ok, pid} = HardwareLink.start_link(%{owner: nil, peer_interface: nil})
        pid
      end

    # 2) Group interfaces per node
    interface_groups = Enum.chunk_every(link_pids, interfaces_per_node)

    # 3) Start nodes with their interface lists and register ownership
    node_pids =
      for iface_list <- interface_groups do
        {:ok, node_pid} = RAND.Node.start_link(iface_list)
        Enum.each(iface_list, fn iface -> HardwareLink.register_owner(iface, node_pid) end)
        node_pid
      end

    # 4) Connect interfaces randomly, avoiding same-owner connections
    # We'll create a pool of all interfaces and pair them up with constraints.
    # Simple greedy pairing: repeatedly pick an interface and try to find a peer from a different owner.
    :ok = randomly_pair_interfaces(interface_groups)

    # 5) Assign simple word addresses and register them on nodes
    addresses = generate_addresses(length(node_pids))

    Enum.zip(node_pids, addresses)
    |> Enum.each(fn {pid, addr} -> RAND.Node.register_address(pid, addr) end)

    {node_pids, List.flatten(interface_groups)}
  end

  defp randomly_pair_interfaces(interface_groups) do
    all = interface_groups |> List.flatten()
    pair_all(all)
  end

  defp pair_all([]), do: :ok

  defp pair_all([_single]) do
    # Odd count safeguard; shouldn't happen with even degree across nodes
    :ok
  end

  defp pair_all([iface | rest]) do
    owner = HardwareLink.get_owner(iface)
    candidates = Enum.filter(rest, fn r -> HardwareLink.get_owner(r) != owner end)

    case candidates do
      [] ->
        # Fallback: swap with some already paired? For simplicity, just skip this iface.
        pair_all(rest)

      _ ->
        peer = Enum.random(candidates)
        HardwareLink.register_link(iface, peer)
        HardwareLink.register_link(peer, iface)
        pair_all(List.delete(rest, peer))
    end
  end

  @doc """
  Send a message from a source node to a destination node and wait for delivery.
  Returns {:ok, hops} or :timeout.
  """
  def traceroute(nodes, from_idx, to_idx, message) do
    traceroute(nodes, from_idx, to_idx, message, timeout: 1_000)
  end

  # Verbose/tag-enabled overload
  def traceroute(nodes, from_idx, to_idx, message, opts) when is_list(opts) do
    from = Enum.at(nodes, from_idx)
    to = Enum.at(nodes, to_idx)
    verbose = Keyword.get(opts, :verbose, false)
    tag = Keyword.get(opts, :tag)
    ack_route = Keyword.get(opts, :ack_route, false)
    timeout = Keyword.get(opts, :timeout, 1_000)
    ttl = Keyword.get(opts, :ttl)
    payload = wrap_payload(message, verbose, ack_route)
    maybe_set_busy_prob(nodes, opts)
    packet = Packet.make_packet(from, to, payload, ack_to: self(), ttl: ttl || 64)

    state = :sys.get_state(from)
    {:ok, source_ifaces} = state |> Map.fetch(:interface_pids)
    out_iface =
      case RAND.Node.fastest_route(state, to) do
        {{_node, link_id}, _hops} -> link_id
        nil -> Enum.random(source_ifaces)
      end
    spawn(fn -> HardwareLink.transmit_packet(out_iface, packet) end)

    receive do
      {:delivered, ^to, hops, parsed} ->
        maybe_print_trace(nodes, from, to, parsed, hops, verbose, tag)
        {:ok, hops}
    after
      timeout -> :timeout
    end
  end

  def directory(nodes) do
    Enum.with_index(nodes)
    |> Enum.map(fn {pid, idx} -> {idx, RAND.Node.get_address(pid)} end)
  end

  def traceroute_by_address(nodes, from_idx, to_address, message, opts \\ [timeout: 1_000])
  def traceroute_by_address(nodes, from_idx, to_address, message, opts) when is_list(opts) do
    to_pid =
      nodes
      |> Enum.find(fn pid -> RAND.Node.get_address(pid) == to_address end)

    case to_pid do
      nil ->
        {:error, :unknown_address}

      _ ->
        from = Enum.at(nodes, from_idx)
        timeout = Keyword.get(opts, :timeout, 1_000)
        ttl = Keyword.get(opts, :ttl)
        packet = Packet.make_packet(from, to_pid, message, ack_to: self(), ttl: ttl || 64)
        state = :sys.get_state(from)
        {:ok, source_ifaces} = state |> Map.fetch(:interface_pids)
        out_iface =
          case RAND.Node.fastest_route(state, to_pid) do
            {{_node, link_id}, _hops} -> link_id
            nil -> Enum.random(source_ifaces)
          end
        spawn(fn -> HardwareLink.transmit_packet(out_iface, packet) end)

        receive do
          {:delivered, ^to_pid, hops, _parsed} -> {:ok, hops}
        after
          timeout -> :timeout
        end
    end
  end

  # Verbose/tag-enabled overload
  def traceroute_by_address(nodes, from_idx, to_address, message, opts) when is_list(opts) do
    to_pid =
      nodes
      |> Enum.find(fn pid -> RAND.Node.get_address(pid) == to_address end)

    case to_pid do
      nil ->
        {:error, :unknown_address}

      _ ->
        from = Enum.at(nodes, from_idx)
        verbose = Keyword.get(opts, :verbose, false)
        tag = Keyword.get(opts, :tag)
        ack_route = Keyword.get(opts, :ack_route, false)
        timeout = Keyword.get(opts, :timeout, 1_000)
        ttl = Keyword.get(opts, :ttl)
        payload = wrap_payload(message, verbose, ack_route)
        maybe_set_busy_prob(nodes, opts)
        packet = Packet.make_packet(from, to_pid, payload, ack_to: self(), ttl: ttl || 64)
        state = :sys.get_state(from)
        {:ok, source_ifaces} = state |> Map.fetch(:interface_pids)
        out_iface =
          case RAND.Node.fastest_route(state, to_pid) do
            {{_node, link_id}, _hops} -> link_id
            nil -> Enum.random(source_ifaces)
          end
        spawn(fn -> HardwareLink.transmit_packet(out_iface, packet) end)

        receive do
          {:delivered, ^to_pid, hops, parsed} ->
            maybe_print_trace(nodes, from, to_pid, parsed, hops, verbose, tag)
            {:ok, hops}
        after
          timeout -> :timeout
        end
    end
  end

  def traceroute_by_addresses(nodes, from_address, to_address, message, opts \\ [timeout: 1_000])
  def traceroute_by_addresses(nodes, from_address, to_address, message, opts) when is_list(opts) do
    case {resolve_by_address(nodes, from_address), resolve_by_address(nodes, to_address)} do
      {nil, _} -> {:error, {:unknown_from, from_address}}
      {_, nil} -> {:error, {:unknown_to, to_address}}
      {from, to} ->
        timeout = Keyword.get(opts, :timeout, 1_000)
        ttl = Keyword.get(opts, :ttl)
        packet = Packet.make_packet(from, to, message, ack_to: self(), ttl: ttl || 64)
        state = :sys.get_state(from)
        {:ok, source_ifaces} = state |> Map.fetch(:interface_pids)
        out_iface =
          case RAND.Node.fastest_route(state, to) do
            {{_node, link_id}, _hops} -> link_id
            nil -> Enum.random(source_ifaces)
          end
        spawn(fn -> HardwareLink.transmit_packet(out_iface, packet) end)
        receive do
          {:delivered, ^to, hops, _parsed} -> {:ok, hops}
        after
          timeout -> :timeout
        end
    end
  end

  # Verbose/tag-enabled overload
  def traceroute_by_addresses(nodes, from_address, to_address, message, opts)
      when is_list(opts) do
    case {resolve_by_address(nodes, from_address), resolve_by_address(nodes, to_address)} do
      {nil, _} -> {:error, {:unknown_from, from_address}}
      {_, nil} -> {:error, {:unknown_to, to_address}}
      {from, to} ->
        verbose = Keyword.get(opts, :verbose, false)
        tag = Keyword.get(opts, :tag)
        ack_route = Keyword.get(opts, :ack_route, false)
        timeout = Keyword.get(opts, :timeout, 1_000)
        ttl = Keyword.get(opts, :ttl)
        payload = wrap_payload(message, verbose, ack_route)
        maybe_set_busy_prob(nodes, opts)
        packet = Packet.make_packet(from, to, payload, ack_to: self(), ttl: ttl || 64)
        state = :sys.get_state(from)
        {:ok, source_ifaces} = state |> Map.fetch(:interface_pids)
        out_iface =
          case RAND.Node.fastest_route(state, to) do
            {{_node, link_id}, _hops} -> link_id
            nil -> Enum.random(source_ifaces)
          end
        spawn(fn -> HardwareLink.transmit_packet(out_iface, packet) end)
        receive do
          {:delivered, ^to, hops, parsed} ->
            maybe_print_trace(nodes, from, to, parsed, hops, verbose, tag)
            {:ok, hops}
        after
          timeout -> :timeout
        end
    end
  end

  # Explicit alias with indices
  def traceroute_by_indices(nodes, from_idx, to_idx, message, opts \\ []) do
    traceroute(nodes, from_idx, to_idx, message, opts)
  end

  # Verbose traceroute that returns hop-by-hop path and prints classic lines
  def traceroute_detail_by_addresses(nodes, from_address, to_address, payload, timeout \\ 2_000) do
    case {resolve_by_address(nodes, from_address), resolve_by_address(nodes, to_address)} do
      {nil, _} -> {:error, {:unknown_from, from_address}}
      {_, nil} -> {:error, {:unknown_to, to_address}}
      {from, to} ->
        trace = {:trace, [], payload}
        packet = Packet.make_packet(from, to, trace, ack_to: self())
        state = :sys.get_state(from)
        {:ok, source_ifaces} = state |> Map.fetch(:interface_pids)
        out_iface =
          case RAND.Node.fastest_route(state, to) do
            {{_node, link_id}, _hops} -> link_id
            nil -> Enum.random(source_ifaces)
          end
        spawn(fn -> HardwareLink.transmit_packet(out_iface, packet) end)
        receive do
          {:delivered, ^to, hops, parsed} ->
            case parsed do
              %{message: {:trace, path, pay}} ->
                print_traceroute_lines(from_address, to_address, path, hops)
                {:ok, hops, path, pay}
              %{message: other} ->
                {:ok, hops, [], other}
            end
        after
          timeout -> :timeout
        end
    end
  end

  defp print_traceroute_lines(from_addr, to_addr, path, hops) do
    IO.puts("traceroute to #{to_addr} from #{from_addr}, #{hops} hops max")
    path
    |> Enum.with_index(1)
    |> Enum.each(fn {addr, i} -> IO.puts(" #{i}\t#{addr}") end)
  end

  defp maybe_print_trace(_nodes, from_pid, to_pid, parsed, hops, verbose, tag) do
    if verbose do
      from_addr = RAND.Node.get_address(from_pid)
      to_addr = RAND.Node.get_address(to_pid)
      case parsed do
        %{message: {:trace, path, _payload}} ->
          if tag do
            IO.puts("[#{tag}]")
          end
          print_traceroute_lines(from_addr, to_addr, path, hops)
        _ -> :ok
      end
    end
  end

  defp wrap_payload(message, verbose, ack_route) do
    payload = if ack_route, do: {:ack_request, message}, else: message
    if verbose, do: {:trace, [], payload}, else: payload
  end

  # TTL now set at packet creation

  defp maybe_set_busy_prob(nodes, opts) do
    case Keyword.get(opts, :busy_prob) do
      nil -> :ok
      prob ->
        Enum.each(nodes, fn node ->
          case :sys.get_state(node) do
            %{interface_pids: ifaces} -> Enum.each(ifaces, &HardwareLink.set_busy_prob(&1, prob))
            _ -> :ok
          end
        end)
        :ok
    end
  end

  defp resolve_by_address(nodes, address) do
    Enum.find(nodes, fn pid -> RAND.Node.get_address(pid) == address end)
  end

  defp generate_addresses(n) do
    # Very simple word-ish addresses (no external deps): adjective-noun-xxxx
    adjectives = ~w(bright dark quiet loud fast slow red blue green amber silver golden)
    nouns = ~w(fox wolf kite node link mesh stream field river cloud stone)

    for _ <- 1..n do
      a = Enum.random(adjectives)
      b = Enum.random(nouns)
      suffix = Integer.to_string(:rand.uniform(9000) + 1000)
      Enum.join([a, b, suffix], "-")
    end
  end
end
