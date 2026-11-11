# Answer Guide

These are lesson-grounded expected answers, not capture findings or executed test results.

1. Use the chosen interface’s capture-filter control under **Capture → Options → Input**. It acts before packets enter the saved file. Entering `tcp` without starting collection collects nothing.

2. The `tcp` capture filter would exclude ordinary UDP reaching that interface during that window. Because the exercise is conditional, it does not establish that UDP occurred in any case.

3. Enter `tcp` in the display-filter toolbar above the packet list. It could hide UDP already saved in a loaded file. Clearing it could reveal those saved packets. Neither action rewrites the file or collects packets.

4. With no loaded file, the packet list has no evidence to display. Even an empty loaded capture would describe only its documented observation point, time window, and collection rule—not the whole network.

5. The limited interpretation is that no UDP packet matches in that documented, restricted file view. **Cannot conclude UDP did not occur on the network.** If the capture rule is unknown, check the acquisition record and available collection details rather than assuming unrestricted collection.

6. Counts can describe packets in a loaded file and packets currently displayed. They cannot count packets rejected before collection, traffic outside the observation point or window, or all network traffic.

7. A checkable note identifies scope, filter settings, file availability, the display filter, and only results actually observed. With no examined file, record `not examined`. Unknown settings remain `unknown`. The limitation should state that activity beyond documented coverage remains unverified; the next action must not imply missing evidence was recovered.

8. Clear the display filter first. Check what remains in the saved file, then check the capture rule, observation point, and time window. If authorized, inspect a broader historical working copy and document its coverage. Otherwise seek equivalent trusted telemetry or plan a future authorized collection.

> A new capture may show more next time, but it cannot recreate packets the earlier capture did not keep.