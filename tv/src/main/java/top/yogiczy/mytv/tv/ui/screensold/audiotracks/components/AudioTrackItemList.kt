package top.yogiczy.mytv.tv.ui.screensold.audiotracks.components

import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.PaddingValues
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.foundation.lazy.rememberLazyListState
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.snapshotFlow
import androidx.compose.ui.Modifier
import androidx.compose.ui.tooling.preview.Preview
import androidx.compose.ui.unit.dp
import androidx.tv.material3.ListItem
import androidx.tv.material3.RadioButton
import androidx.tv.material3.Text
import kotlinx.coroutines.flow.distinctUntilChanged
import top.yogiczy.mytv.tv.ui.screensold.videoplayer.player.VideoPlayer
import top.yogiczy.mytv.tv.ui.theme.MyTvTheme
import top.yogiczy.mytv.tv.ui.utils.focusOnLaunchedSaveable
import top.yogiczy.mytv.tv.ui.utils.handleKeyEvents
import top.yogiczy.mytv.tv.ui.utils.ifElse
import kotlin.math.max

@Composable
fun AudioTrackItemList(
    modifier: Modifier = Modifier,
    trackListProvider: () -> List<VideoPlayer.Metadata.Audio> = { emptyList() },
    onSelected: (VideoPlayer.Metadata.Audio?) -> Unit = {},
    onUserAction: () -> Unit = {},
) {
    val trackList = trackListProvider()

    val listState =
        rememberLazyListState(max(0, trackList.indexOfFirst { it.isSelected == true } - 2))

    LaunchedEffect(listState) {
        snapshotFlow { listState.isScrollInProgress }
            .distinctUntilChanged()
            .collect { _ -> onUserAction() }
    }

    LazyColumn(
        modifier = modifier,
        state = listState,
        contentPadding = PaddingValues(vertical = 4.dp),
        verticalArrangement = Arrangement.spacedBy(10.dp),
    ) {
        item {
            ListItem(
                modifier = modifier
                    .ifElse(
                        trackList.all { it.isSelected != true },
                        Modifier.focusOnLaunchedSaveable()
                    )
                    .handleKeyEvents(onSelect = { onSelected(null) }),
                selected = false,
                onClick = {},
                headlineContent = { Text("关闭") },
                trailingContent = {
                    RadioButton(selected = trackList.all { it.isSelected != true }, onClick = {})
                },
            )
        }

        items(trackList) { track ->
            AudioTrackItem(
                trackProvider = { track },
                onSelected = { onSelected(track) },
            )
        }
    }
}

@Preview
@Composable
private fun AudioTrackItemListPreview() {
    MyTvTheme {
        AudioTrackItemList(
            trackListProvider = {
                listOf(
                    VideoPlayer.Metadata.Audio(
                        channels = 2,
                        bitrate = 128000,
                    ),
                    VideoPlayer.Metadata.Audio(
                        channels = 10,
                        bitrate = 567000,
                        isSelected = true,
                    )
                )
            },
        )
    }
}